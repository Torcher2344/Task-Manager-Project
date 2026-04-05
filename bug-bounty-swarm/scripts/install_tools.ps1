Write-Host "[tools] Installing recon tools via Go"

$tools = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/lc/gau/v2/cmd/gau@latest"
)

foreach ($tool in $tools) {
    Write-Host "[tools] go install $tool"
    go install $tool
}

Write-Host "[tools] Complete"
