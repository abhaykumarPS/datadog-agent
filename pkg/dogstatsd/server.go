// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package dogstatsd

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/aggregator/ckey"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/listeners"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/mapper"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/packets"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/replay"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/tagset"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var (
	dogstatsdExpvars                  = expvar.NewMap("dogstatsd")
	dogstatsdServiceCheckParseErrors  = expvar.Int{}
	dogstatsdServiceCheckPackets      = expvar.Int{}
	dogstatsdEventParseErrors         = expvar.Int{}
	dogstatsdEventPackets             = expvar.Int{}
	dogstatsdMetricParseErrors        = expvar.Int{}
	dogstatsdMetricPackets            = expvar.Int{}
	dogstatsdPacketsLastSec           = expvar.Int{}
	dogstatsdUnterminatedMetricErrors = expvar.Int{}

	tlmProcessed = telemetry.NewCounter("dogstatsd", "processed",
		[]string{"message_type", "state", "origin"}, "Count of service checks/events/metrics processed by dogstatsd")
	tlmProcessedOk    = tlmProcessed.WithValues("metrics", "ok", "")
	tlmProcessedError = tlmProcessed.WithValues("metrics", "error", "")

	// while we try to add the origin tag in the tlmProcessed metric, we want to
	// avoid having it growing indefinitely, hence this safeguard to limit the
	// size of this cache for long-running agent or environment with a lot of
	// different container IDs.
	maxOriginTagsCached = 200

	tlmChannel            = telemetry.NewHistogramNoOp()
	defaultChannelBuckets = []float64{100, 250, 500, 1000, 10000}
	once                  sync.Once
)

func init() {
	dogstatsdExpvars.Set("ServiceCheckParseErrors", &dogstatsdServiceCheckParseErrors)
	dogstatsdExpvars.Set("ServiceCheckPackets", &dogstatsdServiceCheckPackets)
	dogstatsdExpvars.Set("EventParseErrors", &dogstatsdEventParseErrors)
	dogstatsdExpvars.Set("EventPackets", &dogstatsdEventPackets)
	dogstatsdExpvars.Set("MetricParseErrors", &dogstatsdMetricParseErrors)
	dogstatsdExpvars.Set("MetricPackets", &dogstatsdMetricPackets)
	dogstatsdExpvars.Set("UnterminatedMetricErrors", &dogstatsdUnterminatedMetricErrors)
}

// used in debug mode to add the origin on the processed metric as a tag
type cachedTagsOriginMap struct {
	origin string
	ok     map[string]string
	err    map[string]string
	okCnt  telemetry.SimpleCounter
	errCnt telemetry.SimpleCounter
}

func initLatencyTelemetry() {
	get := func(option string) []float64 {
		if !config.Datadog.IsSet(option) {
			return nil
		}

		buckets, err := config.Datadog.GetFloat64SliceE(option)
		if err != nil {
			log.Errorf("%s, falling back to default values", err)
			return nil
		}
		if len(buckets) == 0 {
			log.Debugf("'%s' is empty, falling back to default values", option)
			return nil
		}
		return buckets
	}

	buckets := get("telemetry.dogstatsd.aggregator_channel_latency_buckets")
	if buckets == nil {
		buckets = defaultChannelBuckets
	}

	tlmChannel = telemetry.NewHistogram(
		"dogstatsd",
		"channel_latency",
		[]string{"message_type"},
		"Time in millisecond to push metrics to the aggregator input buffer",
		buckets)

	listeners.InitTelemetry(get("telemetry.dogstatsd.listeners_latency_buckets"))
	packets.InitTelemetry(get("telemetry.dogstatsd.listeners_channel_latency_buckets"))
}

// Server represent a Dogstatsd server
type Server struct {
	// listeners are the instantiated socket listener (UDS or UDP or both)
	listeners []listeners.StatsdListener

	// demultiplexer will receive the metrics processed by the DogStatsD server,
	// will take care of processing them concurrently if possible, and will
	// also take care of forwarding the metrics to the intake.
	demultiplexer aggregator.Demultiplexer

	// running in their own routine, workers are responsible of parsing the packets
	// and pushing them to the aggregator
	workers []*worker

	packetsIn                 chan packets.Packets
	sharedPacketPool          *packets.Pool
	sharedPacketPoolManager   *packets.PoolManager
	sharedFloat64List         *float64ListPool
	Statistics                *util.Stats
	Started                   bool
	stopChan                  chan bool
	health                    *health.Handle
	metricPrefix              string
	metricPrefixBlacklist     []string
	metricBlocklist           []string
	defaultHostname           string
	histToDist                bool
	histToDistPrefix          string
	extraTags                 []string
	Debug                     *dsdServerDebug
	debugTagsAccumulator      *tagset.HashingTagsAccumulator
	TCapture                  *replay.TrafficCapture
	mapper                    *mapper.MetricMapper
	eolTerminationUDP         bool
	eolTerminationUDS         bool
	eolTerminationNamedPipe   bool
	entityIDPrecedenceEnabled bool
	// disableVerboseLogs is a feature flag to disable the logs capable
	// of flooding the logger output (e.g. parsing messages error).
	// NOTE(remy): this should probably be dropped and use a throttler logger, see
	// package (pkg/trace/logutils) for a possible throttler implemetation.
	disableVerboseLogs bool

	// cachedTlmOriginIds is caching origin -> tlmProcessedOkTags/tlmProcessedErrorTags
	// to avoid escaping these in the heap in this hot path.
	cachedTlmOriginIds map[string]cachedTagsOriginMap
	cachedOrder        []cachedTagsOriginMap // for cache eviction

	// ServerlessMode is set to true if we're running in a serverless environment.
	ServerlessMode     bool
	UdsListenerRunning bool
}

// metricStat holds how many times a metric has been
// processed and when was the last time.
type metricStat struct {
	Name     string    `json:"name"`
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	Tags     string    `json:"tags"`
}

type dsdServerDebug struct {
	sync.Mutex
	// Enabled is an atomic int used as a boolean
	Enabled uint64                         `json:"enabled"`
	Stats   map[ckey.ContextKey]metricStat `json:"stats"`
	// counting number of metrics processed last X seconds
	metricsCounts metricsCountBuckets
	// keyGen is used to generate hashes of the metrics received by dogstatsd
	keyGen *ckey.KeyGenerator
}

// metricsCountBuckets is counting the amount of metrics received for the last 5 seconds.
// It is used to detect spikes.
type metricsCountBuckets struct {
	counts     [5]uint64
	bucketIdx  int
	currentSec time.Time
	metricChan chan struct{}
	closeChan  chan struct{}
}

// NewServer returns a running DogStatsD server.
// If extraTags is nil, they will be read from DD_DOGSTATSD_TAGS if set.
func NewServer(demultiplexer aggregator.Demultiplexer, extraTags []string) (*Server, error) {
	// This needs to be done after the configuration is loaded
	once.Do(initLatencyTelemetry)

	var stats *util.Stats
	if config.Datadog.GetBool("dogstatsd_stats_enable") == true {
		buff := config.Datadog.GetInt("dogstatsd_stats_buffer")
		s, err := util.NewStats(uint32(buff))
		if err != nil {
			log.Errorf("Dogstatsd: unable to start statistics facilities")
		}
		stats = s
		dogstatsdExpvars.Set("PacketsLastSecond", &dogstatsdPacketsLastSec)
	}

	var metricsStatsEnabled uint64 // we're using an uint64 for its atomic capacity
	if config.Datadog.GetBool("dogstatsd_metrics_stats_enable") == true {
		log.Info("Dogstatsd: metrics statistics will be stored.")
		metricsStatsEnabled = 1
	}

	packetsChannel := make(chan packets.Packets, config.Datadog.GetInt("dogstatsd_queue_size"))
	tmpListeners := make([]listeners.StatsdListener, 0, 2)
	capture, err := replay.NewTrafficCapture()
	if err != nil {
		return nil, err
	}

	// sharedPacketPool is used by the packet assembler to retrieve already allocated
	// buffer in order to avoid allocation. The packets are pushed back by the server.
	sharedPacketPool := packets.NewPool(config.Datadog.GetInt("dogstatsd_buffer_size"))
	sharedPacketPoolManager := packets.NewPoolManager(sharedPacketPool)

	udsListenerRunning := false

	socketPath := config.Datadog.GetString("dogstatsd_socket")
	if len(socketPath) > 0 {
		unixListener, err := listeners.NewUDSListener(packetsChannel, sharedPacketPoolManager, capture)
		if err != nil {
			log.Errorf(err.Error())
		} else {
			tmpListeners = append(tmpListeners, unixListener)
			udsListenerRunning = true
		}
	}
	if config.Datadog.GetInt("dogstatsd_port") > 0 {
		udpListener, err := listeners.NewUDPListener(packetsChannel, sharedPacketPoolManager, capture)
		if err != nil {
			log.Errorf(err.Error())
		} else {
			tmpListeners = append(tmpListeners, udpListener)
		}
	}

	pipeName := config.Datadog.GetString("dogstatsd_pipe_name")
	if len(pipeName) > 0 {
		namedPipeListener, err := listeners.NewNamedPipeListener(pipeName, packetsChannel, sharedPacketPoolManager, capture)
		if err != nil {
			log.Errorf("named pipe error: %v", err.Error())
		} else {
			tmpListeners = append(tmpListeners, namedPipeListener)
		}
	}

	if len(tmpListeners) == 0 {
		return nil, fmt.Errorf("listening on neither udp nor socket, please check your configuration")
	}

	// check configuration for custom namespace
	metricPrefix := config.Datadog.GetString("statsd_metric_namespace")
	if metricPrefix != "" && !strings.HasSuffix(metricPrefix, ".") {
		metricPrefix = metricPrefix + "."
	}

	metricPrefixBlacklist := config.Datadog.GetStringSlice("statsd_metric_namespace_blacklist")
	metricBlocklist := config.Datadog.GetStringSlice("statsd_metric_blocklist")

	defaultHostname, err := util.GetHostname(context.TODO())
	if err != nil {
		log.Errorf("Dogstatsd: unable to determine default hostname: %s", err.Error())
	}

	histToDist := config.Datadog.GetBool("histogram_copy_to_distribution")
	histToDistPrefix := config.Datadog.GetString("histogram_copy_to_distribution_prefix")

	if extraTags == nil {
		extraTags = config.Datadog.GetStringSlice("dogstatsd_tags")
	}

	entityIDPrecedenceEnabled := config.Datadog.GetBool("dogstatsd_entity_id_precedence")

	eolTerminationUDP := false
	eolTerminationUDS := false
	eolTerminationNamedPipe := false

	for _, v := range config.Datadog.GetStringSlice("dogstatsd_eol_required") {
		switch v {
		case "udp":
			eolTerminationUDP = true
		case "uds":
			eolTerminationUDS = true
		case "named_pipe":
			eolTerminationNamedPipe = true
		default:
			log.Errorf("Invalid dogstatsd_eol_required value: %s", v)
		}
	}

	s := &Server{
		Started:                   true,
		Statistics:                stats,
		packetsIn:                 packetsChannel,
		sharedPacketPool:          sharedPacketPool,
		sharedPacketPoolManager:   sharedPacketPoolManager,
		sharedFloat64List:         newFloat64ListPool(),
		demultiplexer:             demultiplexer,
		listeners:                 tmpListeners,
		stopChan:                  make(chan bool),
		health:                    health.RegisterLiveness("dogstatsd-main"),
		metricPrefix:              metricPrefix,
		metricPrefixBlacklist:     metricPrefixBlacklist,
		metricBlocklist:           metricBlocklist,
		defaultHostname:           defaultHostname,
		histToDist:                histToDist,
		histToDistPrefix:          histToDistPrefix,
		extraTags:                 extraTags,
		eolTerminationUDP:         eolTerminationUDP,
		eolTerminationUDS:         eolTerminationUDS,
		eolTerminationNamedPipe:   eolTerminationNamedPipe,
		entityIDPrecedenceEnabled: entityIDPrecedenceEnabled,
		disableVerboseLogs:        config.Datadog.GetBool("dogstatsd_disable_verbose_logs"),
		Debug: &dsdServerDebug{
			Stats: make(map[ckey.ContextKey]metricStat),
			metricsCounts: metricsCountBuckets{
				counts:     [5]uint64{0, 0, 0, 0, 0},
				metricChan: make(chan struct{}),
				closeChan:  make(chan struct{}),
			},
			keyGen: ckey.NewKeyGenerator(),
		},
		TCapture:           capture,
		UdsListenerRunning: udsListenerRunning,
		cachedTlmOriginIds: make(map[string]cachedTagsOriginMap),
	}

	// packets forwarding
	// ----------------------

	forwardHost := config.Datadog.GetString("statsd_forward_host")
	forwardPort := config.Datadog.GetInt("statsd_forward_port")
	if forwardHost != "" && forwardPort != 0 {
		forwardAddress := fmt.Sprintf("%s:%d", forwardHost, forwardPort)
		con, err := net.Dial("udp", forwardAddress)
		if err != nil {
			log.Warnf("Could not connect to statsd forward host : %s", err)
		} else {
			s.packetsIn = make(chan packets.Packets, config.Datadog.GetInt("dogstatsd_queue_size"))
			go s.forwarder(con, packetsChannel)
		}
	}

	// start the workers processing the packets read on the socket
	// ----------------------

	s.handleMessages()

	// start the debug loop
	// ----------------------

	if metricsStatsEnabled == 1 {
		s.EnableMetricsStats()
	}

	// map some metric name
	// ----------------------

	cacheSize := config.Datadog.GetInt("dogstatsd_mapper_cache_size")

	mappings, err := config.GetDogstatsdMappingProfiles()
	if err != nil {
		log.Warnf("Could not parse mapping profiles: %v", err)
	} else if len(mappings) != 0 {
		mapperInstance, err := mapper.NewMetricMapper(mappings, cacheSize)
		if err != nil {
			log.Warnf("Could not create metric mapper: %v", err)
		} else {
			s.mapper = mapperInstance
		}
	}
	return s, nil
}

func (s *Server) handleMessages() {
	if s.Statistics != nil {
		go s.Statistics.Process()
		go s.Statistics.Update(&dogstatsdPacketsLastSec)
	}

	for _, l := range s.listeners {
		go l.Listen()
	}

	// Run min(2, GoMaxProcs-2) workers, we dedicate a core to the
	// listener goroutine and another to aggregator + forwarder
	workersCount := runtime.GOMAXPROCS(-1) - 2
	if workersCount < 2 {
		workersCount = 2
	}

	for i := 0; i < workersCount; i++ {
		worker := newWorker(s)
		go worker.run()
		s.workers = append(s.workers, worker)
	}
}

// Capture starts a traffic capture at the specified path and with the specified duration,
// an empty path will default to the default location. Returns an error if any.
func (s *Server) Capture(p string, d time.Duration, compressed bool) error {
	return s.TCapture.Start(p, d, compressed)
}

func (s *Server) forwarder(fcon net.Conn, packetsChannel chan packets.Packets) {
	for {
		select {
		case <-s.stopChan:
			return
		case packets := <-packetsChannel:
			for _, packet := range packets {
				_, err := fcon.Write(packet.Contents)

				if err != nil {
					log.Warnf("Forwarding packet failed : %s", err)
				}
			}
			s.packetsIn <- packets
		}
	}
}

// ServerlessFlush flushes all the data to the aggregator to them send it to the Datadog intake.
func (s *Server) ServerlessFlush() {
	log.Debug("Received a Flush trigger")
	// make all workers flush their aggregated data (in the batcher) to the aggregator.
	for _, w := range s.workers {
		w.flush()
	}
	// flush the aggregator to have the serializer/forwarder send data to the backend.
	agg := s.demultiplexer.Aggregator()
	agg.ServerlessFlush <- true
	<-agg.ServerlessFlushDone
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// ScanLines is an almost identical reimplementation of bufio.ScanLines, but also
// reports if the returned line is newline-terminated
func ScanLines(data []byte, atEOF bool) (advance int, token []byte, eol bool, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, false, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, dropCR(data[0:i]), true, nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), dropCR(data), false, nil
	}
	// Request more data.
	return 0, nil, false, nil
}

func nextMessage(packet *[]byte, eolTermination bool) (message []byte) {
	if len(*packet) == 0 {
		return nil
	}

	advance, message, eol, err := ScanLines(*packet, true)
	if err != nil {
		return nil
	}

	if eolTermination && !eol {
		dogstatsdUnterminatedMetricErrors.Add(1)
		return nil
	}

	*packet = (*packet)[advance:]
	return message
}

func (s *Server) eolEnabled(sourceType packets.SourceType) bool {
	switch sourceType {
	case packets.UDS:
		return s.eolTerminationUDS
	case packets.UDP:
		return s.eolTerminationUDP
	case packets.NamedPipe:
		return s.eolTerminationNamedPipe
	}
	return false
}

func (s *Server) parsePackets(batcher *batcher, parser *parser, packets []*packets.Packet, samples []metrics.MetricSample) []metrics.MetricSample {
	for _, packet := range packets {
		log.Tracef("Dogstatsd receive: %q", packet.Contents)
		for {
			message := nextMessage(&packet.Contents, s.eolEnabled(packet.Source))
			if message == nil {
				break
			}
			if len(message) == 0 {
				continue
			}
			if s.Statistics != nil {
				s.Statistics.StatEvent(1)
			}
			messageType := findMessageType(message)

			switch messageType {
			case serviceCheckType:
				serviceCheck, err := s.parseServiceCheckMessage(parser, message, packet.Origin)
				if err != nil {
					s.errLog("Dogstatsd: error parsing service check '%q': %s", message, err)
					continue
				}
				batcher.appendServiceCheck(serviceCheck)
			case eventType:
				event, err := s.parseEventMessage(parser, message, packet.Origin)
				if err != nil {
					s.errLog("Dogstatsd: error parsing event '%q': %s", message, err)
					continue
				}
				batcher.appendEvent(event)
			case metricSampleType:
				var err error
				samples = samples[0:0]

				debugEnabled := atomic.LoadUint64(&s.Debug.Enabled) == 1

				samples, err = s.parseMetricMessage(samples, parser, message, packet.Origin, debugEnabled)
				if err != nil {
					s.errLog("Dogstatsd: error parsing metric message '%q': %s", message, err)
					continue
				}

				for idx := range samples {
					if debugEnabled {
						s.storeMetricStats(samples[idx])
					}
					batcher.appendSample(samples[idx])
					if s.histToDist && samples[idx].Mtype == metrics.HistogramType {
						distSample := samples[idx].Copy()
						distSample.Name = s.histToDistPrefix + distSample.Name
						distSample.Mtype = metrics.DistributionType
						batcher.appendSample(*distSample)
					}
				}
			}
		}
		s.sharedPacketPoolManager.Put(packet)
	}
	batcher.flush()
	return samples
}

func (s *Server) errLog(format string, params ...interface{}) {
	if s.disableVerboseLogs {
		log.Debugf(format, params...)
	} else {
		log.Errorf(format, params...)
	}
}

// createOriginTagMaps  keeps these in a cache to avoid a lot of heap escape
// that we can't avoid in this hot path
func (s *Server) createOriginTagMaps(origin string) cachedTagsOriginMap {
	okMap := map[string]string{"message_type": "metrics", "state": "ok"}
	errorMap := map[string]string{"message_type": "metrics", "state": "error"}
	okMap["origin"] = origin
	errorMap["origin"] = origin
	maps := cachedTagsOriginMap{
		origin: origin,
		ok:     okMap,
		err:    errorMap,
		okCnt:  tlmProcessed.WithTags(okMap),
		errCnt: tlmProcessed.WithTags(errorMap),
	}

	s.cachedTlmOriginIds[origin] = maps
	s.cachedOrder = append(s.cachedOrder, maps)

	if len(s.cachedOrder) > maxOriginTagsCached {
		// remove the oldest one from the cache
		pop := s.cachedOrder[0]
		delete(s.cachedTlmOriginIds, pop.origin)
		s.cachedOrder = s.cachedOrder[1:]
		// remove it from the telemetry metrics as well
		tlmProcessed.DeleteWithTags(pop.ok)
		tlmProcessed.DeleteWithTags(pop.err)
	}

	return maps
}

func (s *Server) parseMetricMessage(metricSamples []metrics.MetricSample, parser *parser, message []byte, origin string, telemetry bool) ([]metrics.MetricSample, error) {
	okCnt := tlmProcessedOk
	errorCnt := tlmProcessedError
	if origin != "" && telemetry {
		var maps cachedTagsOriginMap // errorMap and okMap for this origin
		var exists bool
		if maps, exists = s.cachedTlmOriginIds[origin]; !exists {
			maps = s.createOriginTagMaps(origin)
		}
		okCnt = maps.okCnt
		errorCnt = maps.errCnt
	}

	sample, err := parser.parseMetricSample(message)
	if err != nil {
		dogstatsdMetricParseErrors.Add(1)
		errorCnt.Inc()
		return metricSamples, err
	}

	if s.mapper != nil {
		mapResult := s.mapper.Map(sample.name)
		if mapResult != nil {
			log.Tracef("Dogstatsd mapper: metric mapped from %q to %q with tags %v", sample.name, mapResult.Name, mapResult.Tags)
			sample.name = mapResult.Name
			sample.tags = append(sample.tags, mapResult.Tags...)
		}
	}
	metricSamples = enrichMetricSample(metricSamples, sample, s.metricPrefix, s.metricPrefixBlacklist, s.metricBlocklist, s.defaultHostname, origin, s.entityIDPrecedenceEnabled, s.ServerlessMode)

	if len(sample.values) > 0 {
		s.sharedFloat64List.put(sample.values)
	}

	for idx := range metricSamples {
		// All metricSamples already share the same Tags slice. We can
		// extends the first one and reuse it for the rest.
		if idx == 0 {
			metricSamples[idx].Tags = append(metricSamples[idx].Tags, s.extraTags...)
		} else {
			metricSamples[idx].Tags = metricSamples[0].Tags
		}
		dogstatsdMetricPackets.Add(1)
		okCnt.Inc()
	}
	return metricSamples, nil
}

func (s *Server) parseEventMessage(parser *parser, message []byte, origin string) (*metrics.Event, error) {
	sample, err := parser.parseEvent(message)
	if err != nil {
		dogstatsdEventParseErrors.Add(1)
		tlmProcessed.Inc("events", "error", "")
		return nil, err
	}
	event := enrichEvent(sample, s.defaultHostname, origin, s.entityIDPrecedenceEnabled)
	event.Tags = append(event.Tags, s.extraTags...)
	tlmProcessed.Inc("events", "ok", "")
	dogstatsdEventPackets.Add(1)
	return event, nil
}

func (s *Server) parseServiceCheckMessage(parser *parser, message []byte, origin string) (*metrics.ServiceCheck, error) {
	sample, err := parser.parseServiceCheck(message)
	if err != nil {
		dogstatsdServiceCheckParseErrors.Add(1)
		tlmProcessed.Inc("service_checks", "error", "")
		return nil, err
	}
	serviceCheck := enrichServiceCheck(sample, s.defaultHostname, origin, s.entityIDPrecedenceEnabled)
	serviceCheck.Tags = append(serviceCheck.Tags, s.extraTags...)
	dogstatsdServiceCheckPackets.Add(1)
	tlmProcessed.Inc("service_checks", "ok", "")
	return serviceCheck, nil
}

// Stop stops a running Dogstatsd server
func (s *Server) Stop() {
	close(s.stopChan)
	for _, l := range s.listeners {
		l.Stop()
	}
	if s.Statistics != nil {
		s.Statistics.Stop()
	}
	if s.TCapture != nil {
		s.TCapture.Stop()
	}
	s.health.Deregister() //nolint:errcheck
	s.Started = false
}

// storeMetricStats stores stats on the given metric sample.
//
// It can help troubleshooting clients with bad behaviors.
func (s *Server) storeMetricStats(sample metrics.MetricSample) {
	now := time.Now()
	s.Debug.Lock()
	defer s.Debug.Unlock()

	if s.debugTagsAccumulator == nil {
		s.debugTagsAccumulator = tagset.NewHashingTagsAccumulator()
	}

	// key
	defer s.debugTagsAccumulator.Reset()
	s.debugTagsAccumulator.Append(sample.Tags...)
	key := s.Debug.keyGen.Generate(sample.Name, "", s.debugTagsAccumulator)

	// store
	ms := s.Debug.Stats[key]
	ms.Count++
	ms.LastSeen = now
	ms.Name = sample.Name
	ms.Tags = strings.Join(s.debugTagsAccumulator.Get(), " ") // we don't want/need to share the underlying array
	s.Debug.Stats[key] = ms

	s.Debug.metricsCounts.metricChan <- struct{}{}
}

// EnableMetricsStats enables the debug mode of the DogStatsD server and start
// the debug mainloop collecting the amount of metrics received.
func (s *Server) EnableMetricsStats() {
	s.Debug.Lock()
	defer s.Debug.Unlock()

	// already enabled?
	if atomic.LoadUint64(&s.Debug.Enabled) == 1 {
		return
	}

	atomic.StoreUint64(&s.Debug.Enabled, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond * 100)
		var closed bool
		log.Debug("Starting the DogStatsD debug loop.")
		for {
			select {
			case <-ticker.C:
				sec := time.Now().Truncate(time.Second)
				if sec.After(s.Debug.metricsCounts.currentSec) {
					s.Debug.metricsCounts.currentSec = sec

					if s.hasSpike() {
						log.Warnf("A burst of metrics has been detected by DogStatSd: here is the last 5 seconds count of metrics: %v", s.Debug.metricsCounts.counts)
					}

					s.Debug.metricsCounts.bucketIdx++
					if s.Debug.metricsCounts.bucketIdx >= len(s.Debug.metricsCounts.counts) {
						s.Debug.metricsCounts.bucketIdx = 0
					}

					s.Debug.metricsCounts.counts[s.Debug.metricsCounts.bucketIdx] = 0
				}
			case <-s.Debug.metricsCounts.metricChan:
				s.Debug.metricsCounts.counts[s.Debug.metricsCounts.bucketIdx]++
			case <-s.Debug.metricsCounts.closeChan:
				closed = true
				break
			}

			if closed {
				break
			}
		}
		log.Debug("Stopping the DogStatsD debug loop.")
		ticker.Stop()
	}()
}

func (s *Server) hasSpike() bool {
	// compare this one to the sum of all others
	// if the difference is higher than all others sum, consider this
	// as an anomaly.
	var sum uint64
	for _, v := range s.Debug.metricsCounts.counts {
		sum += v
	}
	sum -= s.Debug.metricsCounts.counts[s.Debug.metricsCounts.bucketIdx]
	if s.Debug.metricsCounts.counts[s.Debug.metricsCounts.bucketIdx] > sum {
		return true
	}
	return false
}

// DisableMetricsStats disables the debug mode of the DogStatsD server and
// stops the debug mainloop.
func (s *Server) DisableMetricsStats() {
	s.Debug.Lock()
	defer s.Debug.Unlock()

	if atomic.LoadUint64(&s.Debug.Enabled) == 1 {
		atomic.StoreUint64(&s.Debug.Enabled, 0)
		s.Debug.metricsCounts.closeChan <- struct{}{}
	}

	log.Info("Disabling DogStatsD debug metrics stats.")
}

// GetJSONDebugStats returns jsonified debug statistics.
func (s *Server) GetJSONDebugStats() ([]byte, error) {
	s.Debug.Lock()
	defer s.Debug.Unlock()
	return json.Marshal(s.Debug.Stats)
}

// FormatDebugStats returns a printable version of debug stats.
func FormatDebugStats(stats []byte) (string, error) {
	var dogStats map[uint64]metricStat
	if err := json.Unmarshal(stats, &dogStats); err != nil {
		return "", err
	}

	// put metrics in order: first is the more frequent
	order := make([]uint64, len(dogStats))
	i := 0
	for metric := range dogStats {
		order[i] = metric
		i++
	}

	sort.Slice(order, func(i, j int) bool {
		return dogStats[order[i]].Count > dogStats[order[j]].Count
	})

	// write the response
	buf := bytes.NewBuffer(nil)

	header := fmt.Sprintf("%-40s | %-20s | %-10s | %-20s\n", "Metric", "Tags", "Count", "Last Seen")
	buf.Write([]byte(header))
	buf.Write([]byte(strings.Repeat("-", len(header)) + "\n"))

	for _, key := range order {
		stats := dogStats[key]
		buf.Write([]byte(fmt.Sprintf("%-40s | %-20s | %-10d | %-20v\n", stats.Name, stats.Tags, stats.Count, stats.LastSeen)))
	}

	if len(dogStats) == 0 {
		buf.Write([]byte("No metrics processed yet."))
	}

	return buf.String(), nil
}

// SetExtraTags sets extra tags. All metrics sent to the DogstatsD will be tagged with them.
func (s *Server) SetExtraTags(tags []string) {
	s.extraTags = tags
}
