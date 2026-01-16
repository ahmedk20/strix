from typing import Any, Literal

from strix.tools.registry import register_tool


@register_tool
def subdomain_recon_execute(
    domain: str,
    subfinder_timeout: int = 60,
    httpx_timeout: int = 120,
    httpx_threads: int = 50,
    httpx_ports: list[int] | None = None,
    output_format: Literal["summary", "detailed", "full"] = "summary",
    include_inactive: bool = False,
) -> dict[str, Any]:
    """
    Execute subdomain discovery and HTTP probing workflow.

    This tool chains subfinder and httpx to efficiently discover subdomains
    and probe for active HTTP/HTTPS services.

    Workflow:
    1. Run subfinder to discover subdomains (JSON output)
    2. Parse subfinder results
    3. Run httpx on discovered subdomains (JSON output)
    4. Parse and structure results
    5. Return agent-friendly summary

    Args:
        domain: Target domain to enumerate (e.g., "example.com")
        subfinder_timeout: Timeout in seconds for subfinder execution (default: 60)
        httpx_timeout: Timeout in seconds for httpx probing (default: 120)
        httpx_threads: Number of concurrent httpx threads (default: 50)
        httpx_ports: Custom ports to probe (e.g., [80, 443, 8080])
        output_format: Result detail level ("summary", "detailed", "full")
        include_inactive: Include subdomains that didn't respond (default: False)

    Returns:
        dict with keys:
        - success: Boolean indicating workflow completion
        - domain: Target domain
        - subdomains_discovered: Total subdomains found
        - active_hosts: Number of hosts responding to HTTP/HTTPS
        - active_urls: List of active URLs (summary format)
        - hosts: Detailed host information (detailed/full formats)
        - status_breakdown: Count of hosts by HTTP status code
        - technology_summary: Detected technologies (detailed format)
        - error: Error message if workflow failed
    """
    from .subdomain_recon_manager import SubdomainReconManager

    manager = SubdomainReconManager()

    try:
        return manager.execute_workflow(
            domain=domain,
            subfinder_timeout=subfinder_timeout,
            httpx_timeout=httpx_timeout,
            httpx_threads=httpx_threads,
            httpx_ports=httpx_ports,
            output_format=output_format,
            include_inactive=include_inactive,
        )
    except (ValueError, RuntimeError, TimeoutError) as e:
        return {
            "success": False,
            "error": str(e),
            "domain": domain,
            "subdomains_discovered": 0,
            "active_hosts": 0,
        }
