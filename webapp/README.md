# CORE TopoGen Web GUI

A web-based GUI for uploading and running CORE topology scenarios.

## Usage

1. Build the Docker image:

```bash
docker build -t core-topogen-webapp ./webapp
```

2. Run the container:

```bash
docker run -p 9090:9090 core-topogen-webapp
```

3. Open your browser to [http://localhost:9090](http://localhost:9090)

## Features
- Upload scenario XML files
- Clean Bootstrap UI
- Ready for backend integration with core-topo-gen logic
