# 🤖 PegaSpy Automation Manager

## Overview

The PegaSpy Automation Manager provides unified control over the entire PegaSpy ecosystem through a single command interface. It manages all three core components:

- **Go Backend** (Port 8080) - High-performance API server
- **Python Legacy** (Port 5000) - Original framework with web dashboard
- **React Native Mobile App** (Port 8081) - Cross-platform mobile interface

## 🚀 Quick Start

### Single Command Management

```bash
# Start all services
./pegaspy start

# Check status
./pegaspy status

# Run health checks
./pegaspy health

# Stop all services
./pegaspy stop
```

### Alternative Usage

```bash
# Using Python directly
python3 pegaspy-manager.py start

# Using the executable script
./pegaspy-manager.py start
```

## 📋 Available Commands

### `start` - Start All Services
Starts the complete PegaSpy ecosystem in the correct order:
1. Checks system dependencies (Go, Python, Node.js, npm)
2. Starts Go backend server
3. Starts Python legacy framework
4. Starts React Native mobile app
5. Runs health checks to verify everything is working

```bash
./pegaspy start
```

**Output Example:**
```
🚀 Starting PegaSpy ecosystem...
🔍 Checking dependencies...
✅ Go: go version go1.21.0 darwin/amd64
✅ Python: Python 3.11.5
✅ Node.js: v18.17.0
✅ npm: 9.6.7
🚀 Starting go-backend...
✅ go-backend started successfully (PID: 12345)
🚀 Starting python-legacy...
✅ python-legacy started successfully (PID: 12346)
🚀 Starting mobile-app...
✅ mobile-app started successfully (PID: 12347)
✅ All services started successfully
🎉 PegaSpy ecosystem is fully operational!
📊 Access points:
   • Go Backend API: http://localhost:8080
   • Python Dashboard: http://127.0.0.1:5000
   • Mobile App: Scan QR code in terminal
```

### `stop` - Stop All Services
Gracefully stops all running services with proper cleanup.

```bash
./pegaspy stop
```

### `restart` - Restart All Services
Stops all services and starts them again.

```bash
./pegaspy restart
```

### `status` - Check Service Status
Displays the current status of all services including:
- Running state (🟢/🔴)
- Process ID (PID)
- Port numbers
- Health status
- Error messages (if any)

```bash
./pegaspy status
```

**Output Example:**
```
📊 PegaSpy Service Status
==================================================
✅ go-backend:
   Running: 🟢 Yes
   PID: 12345
   Port: 8080
   Response Time: 15.2ms

✅ python-legacy:
   Running: 🟢 Yes
   PID: 12346
   Port: 5000
   Response Time: 23.1ms

✅ mobile-app:
   Running: 🟢 Yes
   PID: 12347
   Port: 8081
```

### `health` - Run Health Checks
Performs comprehensive health checks on all services and returns detailed JSON report.

```bash
./pegaspy health
```

**Features:**
- HTTP endpoint testing
- Response time measurement
- Service availability detection
- API functionality verification
- JSON formatted output for automation

### `test` - Run Comprehensive Tests
Executes a full test suite including:
- Health checks for all services
- API endpoint functionality tests
- ML prediction API testing
- Scan functionality verification
- Performance measurements

```bash
./pegaspy test
```

**Output Example:**
```
🧪 Running comprehensive tests...
🏥 Running health checks...
✅ go-backend: Healthy (PID: 12345, Response: 13.85ms)
✅ python-legacy: Healthy (PID: 12346, Response: 23.63ms)
✅ mobile-app: Healthy (PID: 12347, Response: Nonems)

🔬 Testing API functionality...
✅ Scan API: Working
✅ ML Prediction API: Working
📄 Test report saved to: test_report_1754324074.json
```

### `logs` - Show Service Logs
Displays recent logs from all running services.

```bash
./pegaspy logs
```

## 🔧 Advanced Features

### Automatic Dependency Checking
The manager automatically verifies that all required dependencies are installed:
- Go (for backend compilation)
- Python 3 (for legacy framework)
- Node.js (for mobile app)
- npm (for package management)

### External Service Detection
The manager can detect and monitor services that were started outside of its control by:
- Checking HTTP endpoints
- Monitoring port usage
- Identifying process IDs

### Health Monitoring
Continuous health monitoring includes:
- HTTP response time measurement
- Service availability checking
- API endpoint functionality testing
- Error detection and reporting

### Test Report Generation
Comprehensive test reports are automatically generated in JSON format with:
- Timestamp information
- Service health status
- API test results
- Performance metrics

## 📊 Service Details

### Go Backend (Port 8080)
- **Health Endpoint**: `http://localhost:8080/health`
- **API Documentation**: `http://localhost:8080/docs`
- **Dashboard**: `http://localhost:8080/dashboard`
- **Features**: ML detection, blockchain audit, real-time monitoring

### Python Legacy (Port 5000)
- **Health Endpoint**: `http://127.0.0.1:5000/`
- **Web Dashboard**: Full featured security interface
- **Features**: C2 infrastructure, exploit delivery, prevention hardening

### React Native Mobile App (Port 8081)
- **Framework**: Expo development server
- **Access**: QR code scanning for device testing
- **Features**: Mobile security scanning, threat monitoring

## 🛠️ Configuration

### Environment Variables
The manager respects the following environment variables:
- `VIRTUAL_ENV`: Python virtual environment path
- `PATH`: Extended to include virtual environment binaries

### Service Configuration
Each service configuration includes:
- Command to execute
- Working directory
- Port number
- Health check URL
- Environment variables

## 🔍 Troubleshooting

### Common Issues

**Services won't start:**
```bash
# Check dependencies
./pegaspy health

# Check if ports are already in use
lsof -i :8080
lsof -i :5000
lsof -i :8081
```

**Health checks failing:**
```bash
# Test individual endpoints
curl http://localhost:8080/health
curl http://127.0.0.1:5000/
```

**Permission errors:**
```bash
# Make scripts executable
chmod +x pegaspy
chmod +x pegaspy-manager.py
```

### Log Files
- **Manager logs**: `pegaspy-manager.log`
- **Test reports**: `test_report_*.json`
- **Service logs**: Individual service output

## 🚀 Integration Examples

### CI/CD Pipeline
```bash
#!/bin/bash
# Start services for testing
./pegaspy start

# Wait for services to be ready
sleep 10

# Run tests
./pegaspy test

# Check if tests passed
if [ $? -eq 0 ]; then
    echo "✅ All tests passed"
else
    echo "❌ Tests failed"
    ./pegaspy logs
    exit 1
fi

# Cleanup
./pegaspy stop
```

### Monitoring Script
```bash
#!/bin/bash
# Continuous monitoring
while true; do
    ./pegaspy health > health_status.json
    
    # Check if any service is unhealthy
    if grep -q '"overall_status": "unhealthy"' health_status.json; then
        echo "⚠️ Unhealthy services detected, restarting..."
        ./pegaspy restart
    fi
    
    sleep 60
done
```

### Development Workflow
```bash
# Start development environment
./pegaspy start

# Make code changes...

# Test changes
./pegaspy test

# Restart if needed
./pegaspy restart

# Stop when done
./pegaspy stop
```

## 📈 Performance Monitoring

The automation manager provides detailed performance metrics:

- **Response Times**: HTTP endpoint response measurements
- **Resource Usage**: Process monitoring and PID tracking
- **Availability**: Service uptime and health status
- **API Performance**: Endpoint functionality and speed testing

## 🔐 Security Considerations

- Services run with appropriate user permissions
- Health checks use secure HTTP connections
- Process management includes proper cleanup
- Log files contain no sensitive information
- External service detection is read-only

---

## 🎯 Quick Reference

| Command | Purpose | Output |
|---------|---------|--------|
| `./pegaspy start` | Start all services | Status messages |
| `./pegaspy stop` | Stop all services | Cleanup messages |
| `./pegaspy status` | Check service status | Service details |
| `./pegaspy health` | Health checks | JSON report |
| `./pegaspy test` | Run tests | Test results |
| `./pegaspy logs` | Show logs | Service output |
| `./pegaspy restart` | Restart all | Combined stop/start |

**🕷️ PegaSpy Automation Manager - Simplifying Security Operations** 🕷️