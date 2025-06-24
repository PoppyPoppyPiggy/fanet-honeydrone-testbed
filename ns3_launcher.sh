#!/bin/bash
# Enhanced NS3 FANET Honeydrone Launcher Script
# Comprehensive automation for simulation setup and execution

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="$PROJECT_ROOT/ns-allinone-3.40/ns-3.40"
LOGS_DIR="$PROJECT_ROOT/logs"
DATA_DIR="$PROJECT_ROOT/data"
RESULTS_DIR="$PROJECT_ROOT/results"

# Default simulation parameters
DEFAULT_DURATION=300
DEFAULT_DRONES=10
DEFAULT_HONEYPOTS=5
DEFAULT_ATTACK="mixed"
DEFAULT_MTD="true"

# Function definitions
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              NS3 FANET Honeydrone Testbed Launcher          ║"
    echo "║                Enhanced Integration System                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

show_help() {
    cat << EOF
NS3 FANET Honeydrone Launcher - Enhanced Integration

Usage: $0 [OPTIONS] [COMMAND]

COMMANDS:
    setup           - Setup and configure NS3 environment
    build           - Build NS3 simulation
    run             - Run simulation
    clean           - Clean build artifacts
    install-deps    - Install dependencies
    status          - Check system status
    full            - Full setup, build, and run sequence
    bridge          - Start Python bridge only
    dashboard       - Launch web dashboard
    test            - Run test simulation

OPTIONS:
    -d, --duration SECS     Simulation duration (default: $DEFAULT_DURATION)
    -n, --drones NUM        Number of drones (default: $DEFAULT_DRONES)
    -h, --honeypots NUM     Number of honeypots (default: $DEFAULT_HONEYPOTS)
    -a, --attack TYPE       Attack scenario: none|jamming|spoofing|mixed (default: $DEFAULT_ATTACK)
    -m, --mtd BOOL          Enable MTD: true|false (default: $DEFAULT_MTD)
    -v, --verbose           Verbose output
    -w, --websocket         Enable WebSocket server
    -g, --gui               Enable GUI/animation
    -e, --export DIR        Export results to directory
    --help                  Show this help

EXAMPLES:
    $0 setup                                # Setup environment
    $0 run -d 600 -n 20 -h 10              # Run with custom parameters
    $0 full -a jamming -m true -w          # Full run with jamming attack and WebSocket
    $0 bridge                               # Start bridge for external control
    $0 dashboard                            # Launch web dashboard

ENVIRONMENT:
    NS3_PATH        - Override NS3 installation path
    PYTHON_ENV      - Python virtual environment path
    LOG_LEVEL       - Logging level (DEBUG, INFO, WARN, ERROR)

EOF
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        missing_deps+=("python3-pip")
    fi
    
    # Check required Python packages
    local python_packages=(
        "numpy"
        "matplotlib"
        "websockets"
        "asyncio"
    )
    
    for package in "${python_packages[@]}"; do
        if ! python3 -c "import $package" &> /dev/null; then
            log_warn "Python package '$package' not found"
        fi
    done
    
    # Check build tools
    if ! command -v g++ &> /dev/null; then
        missing_deps+=("g++")
    fi
    
    if ! command -v cmake &> /dev/null; then
        missing_deps+=("cmake")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Run '$0 install-deps' to install missing dependencies"
        return 1
    fi
    
    log_info "All dependencies satisfied"
    return 0
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            log_info "Installing packages for Debian/Ubuntu..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                python3 \
                python3-pip \
                python3-dev \
                python3-venv \
                libxml2-dev \
                libxml2-utils \
                libxslt-dev \
                libssl-dev \
                libffi-dev \
                qt5-default \
                gir1.2-goocanvas-2.0 \
                python3-gi \
                python3-gi-cairo \
                python3-pygraphviz \
                gir1.2-gtk-3.0 \
                ipython3 \
                openmpi-bin \
                openmpi-common \
                openmpi-doc \
                libopenmpi-dev \
                mercurial \
                unzip \
                gdb \
                valgrind \
                gsl-bin \
                libgsl-dev \
                libgslcblas0 \
                sqlite3 \
                libsqlite3-dev \
                tcpdump \
                wireshark
        elif command -v yum &> /dev/null; then
            # RedHat/CentOS
            log_info "Installing packages for RedHat/CentOS..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                cmake \
                python3 \
                python3-pip \
                python3-devel \
                libxml2-devel \
                libxslt-devel \
                openssl-devel \
                libffi-devel \
                qt5-qtbase-devel \
                mercurial \
                unzip \
                gdb \
                valgrind \
                gsl-devel \
                sqlite-devel \
                tcpdump \
                wireshark
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            log_info "Installing packages for Arch Linux..."
            sudo pacman -S --noconfirm \
                base-devel \
                cmake \
                python \
                python-pip \
                libxml2 \
                libxslt \
                openssl \
                qt5-base \
                mercurial \
                unzip \
                gdb \
                valgrind \
                gsl \
                sqlite \
                tcpdump \
                wireshark-qt
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        log_info "Installing packages for macOS..."
        if command -v brew &> /dev/null; then
            brew install \
                cmake \
                python3 \
                libxml2 \
                libxslt \
                openssl \
                qt5 \
                mercurial \
                gdb \
                gsl \
                sqlite \
                tcpdump \
                wireshark
        else
            log_error "Homebrew not found. Please install Homebrew first."
            return 1
        fi
    else
        log_warn "Unsupported OS: $OSTYPE"
        log_info "Please install dependencies manually"
    fi
    
    # Install Python packages
    log_info "Installing Python packages..."
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        pip3 install -r "$PROJECT_ROOT/requirements.txt"
    else
        pip3 install numpy matplotlib websockets asyncio sqlite3
    fi
    
    log_info "Dependencies installation completed"
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Create necessary directories
    mkdir -p "$LOGS_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$PROJECT_ROOT/config"
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "$PROJECT_ROOT/venv" ]]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv "$PROJECT_ROOT/venv"
    fi
    
    # Activate virtual environment
    source "$PROJECT_ROOT/venv/bin/activate"
    
    # Install Python requirements
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        log_info "Installing Python requirements..."
        pip install -r "$PROJECT_ROOT/requirements.txt"
    fi
    
    # Setup NS3 if not already done
    if [[ ! -d "$NS3_DIR" ]]; then
        log_info "NS3 not found. Setting up NS3..."
        setup_ns3
    fi
    
    # Copy simulation files to NS3 scratch directory
    copy_simulation_files
    
    log_info "Environment setup completed"
}

setup_ns3() {
    log_info "Setting up NS3..."
    
    local ns3_version="3.40"
    local ns3_url="https://www.nsnam.org/releases/ns-allinone-${ns3_version}.tar.bz2"
    local ns3_archive="ns-allinone-${ns3_version}.tar.bz2"
    
    cd "$PROJECT_ROOT"
    
    # Download NS3 if not already present
    if [[ ! -f "$ns3_archive" ]]; then
        log_info "Downloading NS3 version $ns3_version..."
        wget "$ns3_url" || curl -O "$ns3_url"
    fi
    
    # Extract
    if [[ ! -d "ns-allinone-${ns3_version}" ]]; then
        log_info "Extracting NS3..."
        tar -xjf "$ns3_archive"
    fi
    
    # Build NS3
    cd "ns-allinone-${ns3_version}"
    log_info "Building NS3 (this may take a while)..."
    ./build.py --enable-examples --enable-tests
    
    cd "$PROJECT_ROOT"
    log_info "NS3 setup completed"
}

copy_simulation_files() {
    log_info "Copying simulation files to NS3..."
    
    local scratch_dir="$NS3_DIR/scratch"
    mkdir -p "$scratch_dir"
    
    # Copy C++ simulation files
    if [[ -f "$PROJECT_ROOT/fanet_honeydrone_simulation.cc" ]]; then
        cp "$PROJECT_ROOT/fanet_honeydrone_simulation.cc" "$scratch_dir/"
        log_debug "Copied fanet_honeydrone_simulation.cc"
    fi
    
    if [[ -f "$PROJECT_ROOT/fanet_simulation.cc" ]]; then
        cp "$PROJECT_ROOT/fanet_simulation.cc" "$scratch_dir/"
        log_debug "Copied fanet_simulation.cc"
    fi
    
    log_info "Simulation files copied"
}

build_simulation() {
    log_info "Building NS3 simulation..."
    
    if [[ ! -d "$NS3_DIR" ]]; then
        log_error "NS3 directory not found: $NS3_DIR"
        log_info "Run '$0 setup' first"
        return 1
    fi
    
    cd "$NS3_DIR"
    
    # Check if ns3 command exists
    if [[ -f "./ns3" ]]; then
        log_info "Building with ns3 command..."
        ./ns3 build fanet_honeydrone_simulation
    elif [[ -f "./waf" ]]; then
        log_info "Building with waf..."
        python3 waf build
    else
        log_error "Neither ns3 nor waf found in $NS3_DIR"
        return 1
    fi
    
    if [[ $? -eq 0 ]]; then
        log_info "Build completed successfully"
    else
        log_error "Build failed"
        return 1
    fi
    
    cd "$PROJECT_ROOT"
}

start_python_bridge() {
    log_info "Starting Python bridge..."
    
    # Activate virtual environment
    if [[ -f "$PROJECT_ROOT/venv/bin/activate" ]]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    local bridge_args=""
    
    if [[ "$ENABLE_WEBSOCKET" == "true" ]]; then
        bridge_args="$bridge_args --websocket"
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        bridge_args="$bridge_args --verbose"
    fi
    
    if [[ -n "$EXPORT_DIR" ]]; then
        bridge_args="$bridge_args --export $EXPORT_DIR"
    fi
    
    # Start bridge in background
    python3 "$PROJECT_ROOT/ns3_fanet_bridge.py" $bridge_args &
    local bridge_pid=$!
    
    echo $bridge_pid > "$DATA_DIR/bridge.pid"
    log_info "Python bridge started (PID: $bridge_pid)"
    
    # Wait a moment for bridge to initialize
    sleep 2
}

stop_python_bridge() {
    if [[ -f "$DATA_DIR/bridge.pid" ]]; then
        local bridge_pid=$(cat "$DATA_DIR/bridge.pid")
        if kill -0 "$bridge_pid" 2>/dev/null; then
            log_info "Stopping Python bridge (PID: $bridge_pid)..."
            kill "$bridge_pid"
            rm -f "$DATA_DIR/bridge.pid"
        fi
    fi
}

run_simulation() {
    log_info "Running NS3 simulation..."
    
    if [[ ! -d "$NS3_DIR" ]]; then
        log_error "NS3 directory not found: $NS3_DIR"
        return 1
    fi
    
    cd "$NS3_DIR"
    
    # Prepare simulation arguments
    local sim_args=""
    sim_args="$sim_args --nDrones=$DRONES"
    sim_args="$sim_args --nHoneypots=$HONEYPOTS"
    sim_args="$sim_args --simTime=$DURATION"
    sim_args="$sim_args --attackScenario=$ATTACK"
    sim_args="$sim_args --enableMTD=$MTD"
    sim_args="$sim_args --resultsFile=$DATA_DIR/simulation_results.json"
    sim_args="$sim_args --traceFile=$DATA_DIR/simulation_trace.db"
    sim_args="$sim_args --animationFile=$DATA_DIR/fanet_animation.xml"
    
    log_info "Simulation parameters:"
    log_info "  Duration: $DURATION seconds"
    log_info "  Drones: $DRONES"
    log_info "  Honeypots: $HONEYPOTS"
    log_info "  Attack: $ATTACK"
    log_info "  MTD: $MTD"
    
    # Run simulation
    local start_time=$(date +%s)
    
    if [[ -f "./ns3" ]]; then
        log_info "Running with ns3 command..."
        ./ns3 run "fanet_honeydrone_simulation $sim_args"
    elif [[ -f "./waf" ]]; then
        log_info "Running with waf..."
        python3 waf --run "fanet_honeydrone_simulation $sim_args"
    else
        log_error "Neither ns3 nor waf found"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [[ $? -eq 0 ]]; then
        log_info "Simulation completed successfully in ${duration}s"
    else
        log_error "Simulation failed"
        return 1
    fi
    
    cd "$PROJECT_ROOT"
    
    # Process results if they exist
    if [[ -f "$DATA_DIR/simulation_results.json" ]]; then
        log_info "Processing simulation results..."
        process_results
    fi
}

process_results() {
    log_info "Processing simulation results..."
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local results_subdir="$RESULTS_DIR/run_$timestamp"
    mkdir -p "$results_subdir"
    
    # Copy results
    if [[ -f "$DATA_DIR/simulation_results.json" ]]; then
        cp "$DATA_DIR/simulation_results.json" "$results_subdir/"
    fi
    
    if [[ -f "$DATA_DIR/simulation_trace.db" ]]; then
        cp "$DATA_DIR/simulation_trace.db" "$results_subdir/"
    fi
    
    if [[ -f "$DATA_DIR/fanet_animation.xml" ]]; then
        cp "$DATA_DIR/fanet_animation.xml" "$results_subdir/"
    fi
    
    # Generate visualizations using Python bridge
    if [[ -f "$PROJECT_ROOT/venv/bin/activate" ]]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python3 "$PROJECT_ROOT/ns3_fanet_bridge.py" --export "$results_subdir" --visualize
    
    log_info "Results processed and saved to: $results_subdir"
}

start_dashboard() {
    log_info "Starting web dashboard..."
    
    if [[ -f "$PROJECT_ROOT/venv/bin/activate" ]]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    if [[ -f "$PROJECT_ROOT/dashboard/app.py" ]]; then
        cd "$PROJECT_ROOT/dashboard"
        python3 app.py &
        local dashboard_pid=$!
        echo $dashboard_pid > "$DATA_DIR/dashboard.pid"
        log_info "Dashboard started (PID: $dashboard_pid)"
        log_info "Access dashboard at: http://localhost:5000"
    else
        log_error "Dashboard application not found"
        return 1
    fi
    
    cd "$PROJECT_ROOT"
}

stop_dashboard() {
    if [[ -f "$DATA_DIR/dashboard.pid" ]]; then
        local dashboard_pid=$(cat "$DATA_DIR/dashboard.pid")
        if kill -0 "$dashboard_pid" 2>/dev/null; then
            log_info "Stopping dashboard (PID: $dashboard_pid)..."
            kill "$dashboard_pid"
            rm -f "$DATA_DIR/dashboard.pid"
        fi
    fi
}

run_test() {
    log_info "Running test simulation..."
    
    # Set test parameters
    DURATION=60
    DRONES=5
    HONEYPOTS=2
    ATTACK="jamming"
    MTD="true"
    
    # Run quick test
    build_simulation
    if [[ $? -eq 0 ]]; then
        run_simulation
    else
        log_error "Test build failed"
        return 1
    fi
    
    # Verify results
    if [[ -f "$DATA_DIR/simulation_results.json" ]]; then
        log_info "Test completed successfully"
        log_info "Results file created: $(wc -l < "$DATA_DIR/simulation_results.json") lines"
    else
        log_error "Test failed - no results file generated"
        return 1
    fi
}

check_status() {
    log_info "Checking system status..."
    
    echo -e "\n${CYAN}=== Environment Status ===${NC}"
    
    # Check NS3
    if [[ -d "$NS3_DIR" ]]; then
        echo -e "${GREEN}✓${NC} NS3 installed at: $NS3_DIR"
    else
        echo -e "${RED}✗${NC} NS3 not found"
    fi
    
    # Check Python environment
    if [[ -d "$PROJECT_ROOT/venv" ]]; then
        echo -e "${GREEN}✓${NC} Python virtual environment found"
    else
        echo -e "${YELLOW}!${NC} Python virtual environment not found"
    fi
    
    # Check simulation files
    if [[ -f "$NS3_DIR/scratch/fanet_honeydrone_simulation.cc" ]]; then
        echo -e "${GREEN}✓${NC} Simulation files copied to NS3"
    else
        echo -e "${RED}✗${NC} Simulation files not found in NS3"
    fi
    
    # Check running processes
    if [[ -f "$DATA_DIR/bridge.pid" ]]; then
        local bridge_pid=$(cat "$DATA_DIR/bridge.pid")
        if kill -0 "$bridge_pid" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Python bridge running (PID: $bridge_pid)"
        else
            echo -e "${RED}✗${NC} Python bridge not running"
            rm -f "$DATA_DIR/bridge.pid"
        fi
    else
        echo -e "${YELLOW}!${NC} Python bridge not started"
    fi
    
    if [[ -f "$DATA_DIR/dashboard.pid" ]]; then
        local dashboard_pid=$(cat "$DATA_DIR/dashboard.pid")
        if kill -0 "$dashboard_pid" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Dashboard running (PID: $dashboard_pid)"
        else
            echo -e "${RED}✗${NC} Dashboard not running"
            rm -f "$DATA_DIR/dashboard.pid"
        fi
    else
        echo -e "${YELLOW}!${NC} Dashboard not started"
    fi
    
    # Check recent results
    if [[ -f "$DATA_DIR/simulation_results.json" ]]; then
        local result_time=$(stat -c %Y "$DATA_DIR/simulation_results.json" 2>/dev/null || stat -f %m "$DATA_DIR/simulation_results.json" 2>/dev/null)
        local current_time=$(date +%s)
        local age=$((current_time - result_time))
        
        if [[ $age -lt 3600 ]]; then
            echo -e "${GREEN}✓${NC} Recent simulation results available (${age}s ago)"
        else
            echo -e "${YELLOW}!${NC} Old simulation results (${age}s ago)"
        fi
    else
        echo -e "${YELLOW}!${NC} No simulation results found"
    fi
    
    echo ""
}

cleanup() {
    log_info "Cleaning up..."
    
    # Stop running processes
    stop_python_bridge
    stop_dashboard
    
    # Clean NS3 build artifacts
    if [[ -d "$NS3_DIR" ]]; then
        cd "$NS3_DIR"
        if [[ -f "./ns3" ]]; then
            ./ns3 clean
        elif [[ -f "./waf" ]]; then
            python3 waf clean
        fi
        cd "$PROJECT_ROOT"
    fi
    
    # Clean temporary files
    rm -f "$DATA_DIR"/*.pid
    rm -f "$DATA_DIR"/*.log
    rm -f "$DATA_DIR"/simulation_results.json
    rm -f "$DATA_DIR"/simulation_trace.db
    rm -f "$DATA_DIR"/fanet_animation.xml
    
    log_info "Cleanup completed"
}

# Signal handlers
trap 'log_warn "Interrupted by user"; cleanup; exit 1' INT TERM

# Parse command line arguments
DURATION=$DEFAULT_DURATION
DRONES=$DEFAULT_DRONES
HONEYPOTS=$DEFAULT_HONEYPOTS
ATTACK=$DEFAULT_ATTACK
MTD=$DEFAULT_MTD
VERBOSE=false
ENABLE_WEBSOCKET=false
ENABLE_GUI=false
EXPORT_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -n|--drones)
            DRONES="$2"
            shift 2
            ;;
        -h|--honeypots)
            HONEYPOTS="$2"
            shift 2
            ;;
        -a|--attack)
            ATTACK="$2"
            shift 2
            ;;
        -m|--mtd)
            MTD="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -w|--websocket)
            ENABLE_WEBSOCKET=true
            shift
            ;;
        -g|--gui)
            ENABLE_GUI=true
            shift
            ;;
        -e|--export)
            EXPORT_DIR="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            COMMAND="$1"
            shift
            ;;
    esac
done

# Main execution
print_banner

# Execute command
case "${COMMAND:-}" in
    setup)
        check_dependencies
        setup_environment
        ;;
    build)
        build_simulation
        ;;
    run)
        if [[ "$ENABLE_WEBSOCKET" == "true" ]]; then
            start_python_bridge
        fi
        run_simulation
        ;;
    clean)
        cleanup
        ;;
    install-deps)
        install_dependencies
        ;;
    status)
        check_status
        ;;
    full)
        check_dependencies
        setup_environment
        build_simulation
        if [[ "$ENABLE_WEBSOCKET" == "true" ]]; then
            start_python_bridge
        fi
        run_simulation
        ;;
    bridge)
        ENABLE_WEBSOCKET=true
        start_python_bridge
        log_info "Bridge started. Press Ctrl+C to stop."
        wait
        ;;
    dashboard)
        start_dashboard
        log_info "Dashboard started. Press Ctrl+C to stop."
        wait
        ;;
    test)
        run_test
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        echo ""
        show_help
        exit 1
        ;;
esac

log_info "Operation completed successfully"