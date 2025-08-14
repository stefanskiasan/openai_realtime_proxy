#!/bin/bash

# Voice Chat GPT Proxy - Start Script

echo "🎙️ Starting Voice Chat GPT Proxy..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "📝 Please edit .env file and add your OpenAI API key"
    echo "   OPENAI_API_KEY=sk-your-api-key-here"
    exit 1
fi

# Check if OpenAI API key is set
if ! grep -q "OPENAI_API_KEY=sk-" .env; then
    echo "❌ OpenAI API key not found in .env file"
    echo "📝 Please add your OpenAI API key to .env:"
    echo "   OPENAI_API_KEY=sk-your-api-key-here"
    exit 1
fi

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start containers
echo "🐳 Building Docker containers..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check health
echo "🔍 Checking service health..."
if curl -f http://localhost:8080/health >/dev/null 2>&1; then
    echo "✅ Voice Chat GPT Proxy is running!"
    echo ""
    echo "🌐 Services:"
    echo "   - Proxy API: http://localhost:8080"
    echo "   - WebSocket: ws://localhost:8080/ws"
    echo "   - Health Check: http://localhost:8080/health"
    echo "   - Example: Open examples/basic-chat/index.html in your browser"
    echo ""
    echo "📊 Monitoring:"
    echo "   docker-compose logs -f proxy"
    echo "   docker-compose ps"
    echo ""
    echo "🛑 To stop:"
    echo "   docker-compose down"
else
    echo "❌ Service health check failed"
    echo "📋 Check logs:"
    echo "   docker-compose logs proxy"
    exit 1
fi