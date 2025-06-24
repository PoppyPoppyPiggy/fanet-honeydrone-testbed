#!/bin/bash
# enhanced_mtd_launcher.sh - Enhanced MTD System Launcher

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="${PROJECT_DIR}/logs"
DATA_DIR="${PROJECT_DIR}/data"

setup_enhanced_mtd() {
    log_info "Setting up Enhanced MTD System..."
    
    # Create directories
    mkdir -p "$LOGS_DIR" "$DATA_DIR" "${PROJECT_DIR}/config"
    
    # Setup Python environment
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_info "Python virtual environment created"
    fi
    
    source venv/bin/activate
    
    # Install enhanced dependencies
    log_info "Installing enhanced dependencies..."
    pip install --upgrade pip
    pip install numpy scipy matplotlib psutil requests flask flask-socketio asyncio
    
    # Create enhanced MTD config
    cat > config/enhanced_mtd_config.json << 'EOF'
{
    "engine": {
        "adaptive_thresholds": true,
        "learning_mode": true,
        "multi_threading": true,
        "max_concurrent_threats": 10,
        "response_time_target": 0.5
    },
    "detection": {
        "base_detection_rate": 0.8,
        "false_positive_rate": 0.05,
        "threat_correlation": true,
        "behavioral_analysis": true
    },
    "actions": {
        "cooldown_enabled": true,
        "energy_optimization": true,
        "effectiveness_learning": true,
        "parallel_execution": false
    },
    "network": {
        "drone_count": 10,
        "gcs_count": 2,
        "relay_count": 3,
        "coverage_area": 200,
        "energy_simulation": true
    },
    "thresholds": {
        "critical_threat_level": 0.8,
        "emergency_response_time": 0.1,
        "min_energy_reserve": 0.2,
        "max_action_frequency": 5
    }
}
EOF

    log_info "Enhanced MTD configuration created"
}

start_enhanced_mtd() {
    log_info "Starting Enhanced MTD Engine..."
    
    cd "$PROJECT_DIR"
    source venv/bin/activate
    
    # Check if already running
    if [[ -f "$DATA_DIR/enhanced_mtd.pid" ]]; then
        PID=$(cat "$DATA_DIR/enhanced_mtd.pid")
        if kill -0 $PID 2>/dev/null; then
            log_warn "Enhanced MTD Engine already running (PID: $PID)"
            return 0
        else
            rm -f "$DATA_DIR/enhanced_mtd.pid"
        fi
    fi
    
    # Start enhanced MTD engine
    log_info "Launching Enhanced MTD Engine with advanced features..."
    python3 src/enhanced_mtd.py > "$LOGS_DIR/enhanced_mtd.log" 2>&1 &
    MTD_PID=$!
    echo $MTD_PID > "$DATA_DIR/enhanced_mtd.pid"
    
    # Wait a moment and check if it started successfully
    sleep 3
    if kill -0 $MTD_PID 2>/dev/null; then
        log_info "Enhanced MTD Engine started successfully"
        log_info "PID: $MTD_PID"
        log_info "Log: tail -f $LOGS_DIR/enhanced_mtd.log"
        
        # Display initial status
        sleep 2
        show_mtd_status
    else
        log_error "Failed to start Enhanced MTD Engine"
        return 1
    fi
}

stop_enhanced_mtd() {
    log_info "Stopping Enhanced MTD Engine..."
    
    if [[ -f "$DATA_DIR/enhanced_mtd.pid" ]]; then
        PID=$(cat "$DATA_DIR/enhanced_mtd.pid")
        if kill -0 $PID 2>/dev/null; then
            # Send interrupt signal for graceful shutdown
            kill -INT $PID
            
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! kill -0 $PID 2>/dev/null; then
                    log_info "Enhanced MTD Engine stopped gracefully"
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if kill -0 $PID 2>/dev/null; then
                kill -KILL $PID
                log_warn "Enhanced MTD Engine force killed"
            fi
        fi
        rm -f "$DATA_DIR/enhanced_mtd.pid"
    else
        log_warn "Enhanced MTD Engine PID file not found"
    fi
    
    # Clean up any remaining python processes
    pkill -f "enhanced_mtd.py" 2>/dev/null || true
}

show_mtd_status() {
    log_info "Enhanced MTD Engine Status..."
    
    echo -e "\n${BLUE}=== Enhanced MTD System Status ===${NC}"
    
    # Check if running
    if [[ -f "$DATA_DIR/enhanced_mtd.pid" ]]; then
        PID=$(cat "$DATA_DIR/enhanced_mtd.pid")
        if kill -0 $PID 2>/dev/null; then
            echo -e "Status: ${GREEN}RUNNING${NC} (PID: $PID)"
            
            # Get process info
            ps_info=$(ps -p $PID -o pid,ppid,pcpu,pmem,etime,cmd --no-headers 2>/dev/null || echo "Process info unavailable")
            echo "Process: $ps_info"
            
            # Show recent log entries
            if [[ -f "$LOGS_DIR/enhanced_mtd.log" ]]; then
                echo -e "\n${BLUE}Recent Activity:${NC}"
                tail -5 "$LOGS_DIR/enhanced_mtd.log" | while read line; do
                    echo "  $line"
                done
            fi
            
            # Show system resources
            echo -e "\n${BLUE}System Resources:${NC}"
            if command -v free >/dev/null 2>&1; then
                mem_usage=$(free -h | grep '^Mem:' | awk '{print $3"/"$2}')
                echo "  Memory Usage: $mem_usage"
            fi
            
            if command -v uptime >/dev/null 2>&1; then
                load_avg=$(uptime | awk -F'load average:' '{print $2}')
                echo "  Load Average:$load_avg"
            fi
            
        else
            echo -e "Status: ${RED}STOPPED${NC} (PID file exists but process not running)"
        fi
    else
        echo -e "Status: ${RED}STOPPED${NC}"
    fi
    
    # Check DVDS status
    echo -e "\n${BLUE}=== DVDS Integration ===${NC}"
    for port in 8080 5000 3000; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo -e "DVDS Port $port: ${GREEN}ACTIVE${NC}"
            break
        fi
    done
    
    # Check dashboard status
    echo -e "\n${BLUE}=== Dashboard Status ===${NC}"
    if [[ -f "$DATA_DIR/dashboard.pid" ]]; then
        DASH_PID=$(cat "$DATA_DIR/dashboard.pid")
        if kill -0 $DASH_PID 2>/dev/null; then
            dashboard_port=$(netstat -tulpn 2>/dev/null | grep $DASH_PID | grep LISTEN | head -1 | awk '{print $4}' | cut -d: -f2)
            echo -e "Dashboard: ${GREEN}RUNNING${NC} (http://localhost:${dashboard_port:-5001})"
        else
            echo -e "Dashboard: ${RED}STOPPED${NC}"
        fi
    else
        echo -e "Dashboard: ${RED}NOT STARTED${NC}"
    fi
}

show_live_monitoring() {
    log_info "Starting live monitoring mode..."
    echo "Press Ctrl+C to exit"
    
    while true; do
        clear
        echo -e "${BLUE}=== Enhanced MTD Live Monitor ===${NC}"
        echo "Updated: $(date)"
        echo ""
        
        # Show MTD status
        show_mtd_status
        
        # Show recent threats if log exists
        if [[ -f "$LOGS_DIR/enhanced_mtd.log" ]]; then
            echo -e "\n${BLUE}=== Recent Threats & Actions ===${NC}"
            tail -10 "$LOGS_DIR/enhanced_mtd.log" | grep -E "(THREAT DETECTED|EXECUTING MTD|ACTION SUCCESS|ACTION FAILED)" | tail -5 | while read line; do
                if echo "$line" | grep -q "THREAT"; then
                    echo -e "${RED}$line${NC}"
                elif echo "$line" | grep -q "SUCCESS"; then
                    echo -e "${GREEN}$line${NC}"
                elif echo "$line" | grep -q "FAILED"; then
                    echo -e "${YELLOW}$line${NC}"
                else
                    echo "$line"
                fi
            done
        fi
        
        sleep 5
    done
}

run_enhanced_test() {
    log_info "Running Enhanced MTD Test Suite..."
    
    # Start MTD if not running
    if ! [[ -f "$DATA_DIR/enhanced_mtd.pid" ]] || ! kill -0 $(cat "$DATA_DIR/enhanced_mtd.pid") 2>/dev/null; then
        start_enhanced_mtd
        sleep 5
    fi
    
    # Run for 60 seconds and collect stats
    log_info "Running test for 60 seconds..."
    start_time=$(date +%s)
    
    while [[ $(($(date +%s) - start_time)) -lt 60 ]]; do
        echo -n "."
        sleep 2
    done
    
    echo ""
    log_info "Test completed. Generating report..."
    
    # Generate test report
    if [[ -f "$LOGS_DIR/enhanced_mtd.log" ]]; then
        threat_count=$(grep -c "THREAT DETECTED" "$LOGS_DIR/enhanced_mtd.log" || echo "0")
        action_count=$(grep -c "EXECUTING MTD" "$LOGS_DIR/enhanced_mtd.log" || echo "0")
        success_count=$(grep -c "ACTION SUCCESS" "$LOGS_DIR/enhanced_mtd.log" || echo "0")
        
        echo -e "\n${BLUE}=== Test Results ===${NC}"
        echo "Duration: 60 seconds"
        echo "Threats Detected: $threat_count"
        echo "Actions Executed: $action_count"
        echo "Successful Actions: $success_count"
        
        if [[ $action_count -gt 0 ]]; then
            success_rate=$((success_count * 100 / action_count))
            echo "Success Rate: $success_rate%"
        fi
        
        echo "Threats per minute: $((threat_count * 60 / 60))"
        echo "Actions per minute: $((action_count * 60 / 60))"
    fi
}

show_help() {
    cat << EOF
${BLUE}Enhanced MTD System Launcher${NC}

Usage: $0 <command>

${YELLOW}Setup Commands:${NC}
  setup         Setup enhanced MTD system with dependencies
  
${YELLOW}Control Commands:${NC}
  start         Start enhanced MTD engine
  stop          Stop enhanced MTD engine  
  restart       Restart enhanced MTD engine
  status        Show system status
  
${YELLOW}Monitoring Commands:${NC}
  monitor       Live monitoring mode
  logs          Show recent logs
  test          Run test suite
  
${YELLOW}Examples:${NC}
  $0 setup      # Initial setup
  $0 start      # Start the engine
  $0 monitor    # Live monitoring
  $0 test       # Run 60-second test

${YELLOW}Features:${NC}
  🚀 8 Threat Types & 11 MTD Actions
  🧠 Adaptive Learning & Intelligence
  📊 Real-time Metrics & Monitoring
  🔄 Parallel Processing & Optimization
  🌐 Realistic Network Simulation

EOF
}

# Main execution
case "${1:-help}" in
    "setup")
        setup_enhanced_mtd
        ;;
    "start")
        start_enhanced_mtd
        ;;
    "stop")
        stop_enhanced_mtd
        ;;
    "restart")
        stop_enhanced_mtd
        sleep 2
        start_enhanced_mtd
        ;;
    "status")
        show_mtd_status
        ;;
    "monitor")
        show_live_monitoring
        ;;
    "logs")
        if [[ -f "$LOGS_DIR/enhanced_mtd.log" ]]; then
            tail -f "$LOGS_DIR/enhanced_mtd.log"
        else
            log_error "Log file not found"
        fi
        ;;
    "test")
        run_enhanced_test
        ;;
    "help"|*)
        show_help
        ;;
esac