# Datadog Agent

[![CircleCI](https://circleci.com/gh/DataDog/datadog-agent/tree/main.svg?style=svg&circle-token=dbcee3f02b9c3fe5f142bfc5ecb735fdec34b643)](https://circleci.com/gh/DataDog/datadog-agent/tree/main)
[![Windows unit tests](https://github.com/DataDog/datadog-agent/actions/workflows/windows-unittests.yml/badge.svg)](https://github.com/DataDog/datadog-agent/actions/workflows/windows-unittests.yml)
[![Coverage status](https://codecov.io/github/DataDog/datadog-agent/coverage.svg?branch=main)](https://codecov.io/github/DataDog/datadog-agent?branch=main)
[![GoDoc](https://godoc.org/github.com/DataDog/datadog-agent?status.svg)](https://godoc.org/github.com/DataDog/datadog-agent)
[![Go Report Card](https://goreportcard.com/badge/github.com/DataDog/datadog-agent)](https://goreportcard.com/report/github.com/DataDog/datadog-agent)

The present repository contains the source code of the Datadog Agent version 7 and version 6. Please refer to the [Agent user documentation](docs/agent) for information about differences between Agent v5, Agent v6 and Agent v7. Additionally, we provide a list of prepackaged binaries for an easy install process [here](https://app.datadoghq.com/account/settings#agent)

**Note:** the source code of Datadog Agent v5 is located in the
[dd-agent](https://github.com/DataDog/dd-agent) repository.

## Documentation

The general documentation of the project, including instructions for installation
and development, is located under [the docs directory](docs) of the present repo.

## Getting started

To build the Agent you need:
 * [Go](https://golang.org/doc/install) 1.16 or later. You'll also need to set your `$GOPATH` and have `$GOPATH/bin` in your path.
 * Python 3.7+ along with development libraries for tooling. You will also need Python 2.7 if you are building the Agent with Python 2 support.
 * Python dependencies. You may install these with `pip install -r requirements.txt`
   This will also pull in [Invoke](http://www.pyinvoke.org) if not yet installed.
 * CMake version 3.12 or later and a C++ compiler

**Note:** you may want to use a python virtual environment to avoid polluting your
      system-wide python environment with the agent build/dev dependencies. You can
      create a virtual environment using `virtualenv` and then use the `invoke agent.build`
      parameters `--python-home-2=<venv_path>` and/or `--python-home-3=<venv_path>`
      (depending on the python versions you are using) to use the virtual environment's
      interpreter and libraries. By default, this environment is only used for dev dependencies
      listed in `requirements.txt`.

**Note:** You may have previously installed `invoke` via brew on MacOS, or `pip` in
      any other platform. We recommend you use the version pinned in the requirements
      file for a smooth development/build experience.

Builds and tests are orchestrated with `invoke`, type `invoke --list` on a shell
to see the available tasks.

To start working on the Agent, you can build the `main` branch:

1. Checkout the repo: `git clone https://github.com/DataDog/datadog-agent.git $GOPATH/src/github.com/DataDog/datadog-agent`.
2. cd into the project folder: `cd $GOPATH/src/github.com/DataDog/datadog-agent`.
3. Install go tools: `invoke install-tools`.
4. Install go dependencies: `invoke deps`.
   Make sure that `$GOPATH/bin` is in your `$PATH` otherwise this step might fail.
5. Create a development `datadog.yaml` configuration file in `dev/dist/datadog.yaml`, containing a valid API key: `api_key: <API_KEY>`
6. Build the agent with `invoke agent.build --build-exclude=systemd`.

    By default, the Agent will be built to use Python 3 but you can select which Python version you want to use:

      - `invoke agent.build --python-runtimes 2` for Python2 only
      - `invoke agent.build --python-runtimes 3` for Python3 only
      - `invoke agent.build --python-runtimes 2,3` for both Python2 and Python3

     You can specify a custom Python location for the agent (useful when using
     virtualenvs):

       invoke agent.build \
         --python-runtimes 2,3 \
         --python-home-2=$GOPATH/src/github.com/DataDog/datadog-agent/venv2 \
         --python-home-3=$GOPATH/src/github.com/DataDog/datadog-agent/venv3 .

    Running `invoke agent.build`:

     * Discards any changes done in `bin/agent/dist`.
     * Builds the Agent and writes the binary to `bin/agent/agent`.
     * Copies files from `dev/dist` to `bin/agent/dist`. See `https://github.com/DataDog/datadog-agent/blob/main/dev/dist/README.md` for more information.

     If you built an older version of the agent, you may have the error `make: *** No targets specified and no makefile found.  Stop.`. To solve the issue, you should remove `CMakeCache.txt` from `rtloader` folder with `rm rtloader/CMakeCache.txt`.



Please refer to the [Agent Developer Guide](docs/dev/README.md) for more details. For instructions
on setting up a windows dev environment, refer to [Windows Dev Env](devenv).

## Testing

Run tests using `invoke test`. During development, add the `--skip-linters` option to skip straight to the tests.
```
invoke test --targets=./pkg/aggregator/... --skip-linters
```

When testing code that depends on [rtloader](/rtloader), build and install it first.
```
invoke rtloader.make && invoke rtloader.install
invoke test --targets=./pkg/collector/python --skip-linters
```

## Run

You can run the agent with:
```
./bin/agent/agent run -c bin/agent/dist/datadog.yaml
```

The file `bin/agent/dist/datadog.yaml` is copied from `dev/dist/datadog.yaml` by `invoke agent.build` and must contain a valid api key.

## Contributing code

You'll find information and help on how to contribute code to this project under
[the `docs/dev` directory](docs/dev) of the present repo.

## License

The Datadog agent user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code is licensed
under the [General Public License, Version 2.0](pkg/ebpf/c/COPYING).
