# Download data (will go to ~/.mitre-mcp-server/data/)
# Run from the project root dir
python -m mitre_mcp_server.data.download

# Check stats
python -m mitre_mcp_server.data.download --stats

# Verify location
ls -la ~/.mitre-mcp-server/data/