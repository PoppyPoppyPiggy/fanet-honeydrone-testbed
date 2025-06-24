# Set environment variables
export DRONE_ID=${DRONE_ID:-1}
export DRONE_TYPE=${DRONE_TYPE:-virtual}
export MTD_ENABLED=${MTD_ENABLED:-false}
export HONEYPOT_TYPE=${HONEYPOT_TYPE:-none}
export ENERGY_LEVEL=${ENERGY_LEVEL:-100}
export VULNERABILITY_LEVEL=${VULNERABILITY_LEVEL:-0.3}

echo "🚁 Starting HoneyDrone Container"
echo "Drone ID: $DRONE_ID"
echo "Drone Type: $DRONE_TYPE"
echo "MTD Enabled: $MTD_ENABLED"
echo "Honeypot Type: $HONEYPOT_TYPE"

# Start basic services
service ssh start
service apache2 start

# Configuration based on drone type
if [ "$DRONE_TYPE" = "dummy" ]; then
    echo "🎯 Dummy Drone Mode - Enabling Vulnerable Services"

    # Start vulnerable services
    service telnetd start || echo "Failed to start Telnet"
    service vsftpd start || echo "Failed to start FTP"

    # Set weak passwords
    echo 'admin:admin' | chpasswd
    echo 'drone:drone123' | chpasswd
    echo 'pi:raspberry' | chpasswd

    # Start honeypot agent if exists
    if [ -f "/opt/honeydrone/scripts/honeypot_agent.py" ]; then
        python3 /opt/honeydrone/scripts/honeypot_agent.py &
    fi

    echo "✅ Dummy Drone Services Started"
else
    echo "🛡️ Virtual Drone Mode - Only Secure Services Enabled"

    # Set random root password
    echo "root:$(openssl rand -base64 32)" | chpasswd

    # Start MTD agent if enabled
    if [ "$MTD_ENABLED" = "true" ] && [ -f "/opt/honeydrone/scripts/mtd_agent.py" ]; then
        python3 /opt/honeydrone/scripts/mtd_agent.py &
    fi

    echo "✅ Virtual Drone Services Started"
fi

# Always start companion computer simulator
if [ -f "/opt/honeydrone/scripts/companion_simulator.py" ]; then
    python3 /opt/honeydrone/scripts/companion_simulator.py &
    echo "✅ Companion Computer Simulator Started"
fi

# Start MAVLink service
if [ -f "/opt/honeydrone/scripts/mavlink_service.py" ]; then
    python3 /opt/honeydrone/scripts/mavlink_service.py &
    echo "✅ MAVLink Service Started"
fi

echo "🎯 HoneyDrone Container Initialization Complete"

# Keep the container running
exec tail -f /dev/null
