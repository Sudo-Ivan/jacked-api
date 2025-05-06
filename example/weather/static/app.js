// Weather app functionality
let metricsEventSource;

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    // Set up metrics SSE
    setupMetrics();
    
    // Add event listeners
    document.getElementById('searchBtn').addEventListener('click', searchWeather);
    document.getElementById('cityInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            searchWeather();
        }
    });
});

// Format uptime duration
function formatUptime(uptime) {
    const duration = uptime.split(' ')[0];
    const unit = uptime.split(' ')[1];
    
    // Convert to appropriate unit if needed
    if (unit === 's' && parseFloat(duration) >= 60) {
        const minutes = Math.floor(parseFloat(duration) / 60);
        return `${minutes}m`;
    } else if (unit === 'm' && parseFloat(duration) >= 60) {
        const hours = Math.floor(parseFloat(duration) / 60);
        return `${hours}h`;
    }
    
    return uptime;
}

// Set up Server-Sent Events for metrics
function setupMetrics() {
    metricsEventSource = new EventSource('/api/metrics');
    
    metricsEventSource.onmessage = (event) => {
        const metrics = JSON.parse(event.data);
        updateMetrics(metrics);
    };
    
    metricsEventSource.onerror = () => {
        console.error('Metrics SSE connection error');
        metricsEventSource.close();
        // Try to reconnect after 5 seconds
        setTimeout(setupMetrics, 5000);
    };
}

// Update metrics display
function updateMetrics(metrics) {
    document.getElementById('totalRequests').textContent = metrics.total_requests;
    document.getElementById('failedRequests').textContent = metrics.failed_requests;
    document.getElementById('avgResponse').textContent = metrics.average_response.toFixed(2);
    document.getElementById('lastMinuteHits').textContent = metrics.last_minute_hits;
    document.getElementById('uptime').textContent = formatUptime(metrics.uptime);
}

// Search weather for a city
async function searchWeather() {
    const cityInput = document.getElementById('cityInput');
    const city = cityInput.value.trim();
    
    if (!city) {
        showError('Please enter a city name');
        return;
    }
    
    // Show loading state
    setLoading(true);
    hideError();
    
    try {
        const response = await fetch(`/api/weather?city=${encodeURIComponent(city)}`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch weather data');
        }
        
        displayWeather(data);
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
    }
}

// Display weather information
function displayWeather(data) {
    const weatherInfo = document.getElementById('weatherInfo');
    const cityName = document.getElementById('cityName');
    const temperature = document.getElementById('temperature');
    const humidity = document.getElementById('humidity');
    const windSpeed = document.getElementById('windSpeed');
    const description = document.getElementById('description');
    const timestamp = document.getElementById('timestamp');
    const requestTime = document.getElementById('requestTime');
    
    cityName.textContent = data.city;
    temperature.textContent = `${data.temperature.toFixed(1)}°C`;
    humidity.textContent = `${data.humidity}%`;
    windSpeed.textContent = `${data.wind_speed} km/h`;
    description.textContent = data.description;
    timestamp.textContent = new Date(data.timestamp).toLocaleString();
    requestTime.textContent = `${data.request_time}ms`;
    
    weatherInfo.style.display = 'block';
}

// Show loading state
function setLoading(isLoading) {
    const loading = document.getElementById('loading');
    const searchBtn = document.getElementById('searchBtn');
    const cityInput = document.getElementById('cityInput');
    
    loading.style.display = isLoading ? 'block' : 'none';
    searchBtn.disabled = isLoading;
    cityInput.disabled = isLoading;
}

// Show error message
function showError(message) {
    const error = document.getElementById('error');
    error.textContent = message;
    error.style.display = 'block';
}

// Hide error message
function hideError() {
    const error = document.getElementById('error');
    error.style.display = 'none';
} 