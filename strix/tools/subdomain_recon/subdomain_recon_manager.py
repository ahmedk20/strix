import json
import logging
import tempfile
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class SubdomainReconManager:
    """Manager for subdomain reconnaissance workflow."""

    def __init__(self) -> None:
        self.temp_dir = Path(tempfile.gettempdir())

    def execute_workflow(
        self,
        domain: str,
        subfinder_timeout: int,
        httpx_timeout: int,
        httpx_threads: int,
        httpx_ports: list[int] | None,
        output_format: str,
        include_inactive: bool,
    ) -> dict[str, Any]:
        """Execute the full subdomain recon workflow."""

        # Step 1: Run subfinder
        subfinder_result = self._run_subfinder(domain, subfinder_timeout)

        if not subfinder_result["success"]:
            return subfinder_result  # Early exit on failure

        subdomains = subfinder_result["subdomains"]

        if not subdomains:
            return {
                "success": True,
                "domain": domain,
                "subdomains_discovered": 0,
                "active_hosts": 0,
                "message": f"No subdomains discovered for {domain}",
                "active_urls": [],
                "status_breakdown": {},
            }

        # Step 2: Run httpx on discovered subdomains
        httpx_result = self._run_httpx(
            subdomains,
            httpx_timeout,
            httpx_threads,
            httpx_ports,
        )

        if not httpx_result["success"]:
            # Return partial results (subfinder succeeded, httpx failed)
            return {
                "success": False,
                "domain": domain,
                "subdomains_discovered": len(subdomains),
                "active_hosts": 0,
                "error": httpx_result.get("error"),
                "subdomains": subdomains,
            }

        # Step 3: Format results based on output_format
        return self._format_results(
            domain,
            subdomains,
            httpx_result["probed_hosts"],
            output_format,
            include_inactive,
        )

    def _run_subfinder(self, domain: str, timeout: int) -> dict[str, Any]:
        """Execute subfinder and parse JSON output."""
        from strix.tools.terminal.terminal_actions import terminal_execute

        # Create temp file for output
        output_file = self.temp_dir / f"subfinder_{domain.replace('.', '_')}.json"

        try:
            command = f"subfinder -d {domain} -silent -json -o {output_file}"

            result = terminal_execute(
                command=command,
                timeout=float(timeout),
            )

            # Check for errors
            if result.get("status") == "error" or result.get("exit_code") not in [0, None]:
                error_msg = result.get("content", "Unknown error")
                if "command not found" in error_msg.lower():
                    error_msg = "subfinder not found. Ensure tool is installed in environment."
                return {
                    "success": False,
                    "error": f"subfinder failed: {error_msg}",
                }

            # Parse JSON output
            if not output_file.exists():
                return {"success": True, "subdomains": []}

            with output_file.open() as f:
                lines = f.readlines()

            subdomains = []
            for line in lines:
                if line.strip():
                    try:
                        data = json.loads(line)
                        # Subfinder JSON has 'host' field
                        subdomain = data.get("host", data.get("subdomain", ""))
                        if subdomain:
                            subdomains.append(subdomain)
                    except json.JSONDecodeError:
                        # Skip malformed lines
                        continue

            # Cleanup
            output_file.unlink(missing_ok=True)

            return {
                "success": True,
                "subdomains": list(set(subdomains)),  # Deduplicate
            }

        except (OSError, Exception) as e:
            # Cleanup on error
            if output_file.exists():
                output_file.unlink(missing_ok=True)
            return {
                "success": False,
                "error": f"Failed to run/parse subfinder: {e}",
            }

    def _run_httpx(
        self,
        subdomains: list[str],
        timeout: int,
        threads: int,
        ports: list[int] | None,
    ) -> dict[str, Any]:
        """Execute httpx on subdomains and parse JSON output."""
        from strix.tools.terminal.terminal_actions import terminal_execute

        # Write subdomains to temp file
        input_hash = str(hash(tuple(subdomains)))[:8]
        input_file = self.temp_dir / f"httpx_input_{input_hash}.txt"
        output_file = self.temp_dir / f"httpx_output_{input_hash}.json"

        try:
            with input_file.open("w") as f:
                f.write("\n".join(subdomains))

            # Build httpx command
            ports_flag = f"-p {','.join(map(str, ports))}" if ports else ""
            command = (
                f"httpx -l {input_file} "
                f"-silent -json -no-color "
                f"-threads {threads} "
                f"-timeout 10 "
                f"{ports_flag} "
                f"-o {output_file}"
            )

            result = terminal_execute(
                command=command,
                timeout=float(timeout),
            )

            # Check for errors
            if result.get("status") == "error":
                error_msg = result.get("content", "Unknown error")
                if "command not found" in error_msg.lower():
                    error_msg = "httpx not found. Ensure tool is installed in environment."
                return {
                    "success": False,
                    "error": f"httpx failed: {error_msg}",
                }

            # Parse JSON output
            if not output_file.exists():
                return {"success": True, "probed_hosts": []}

            with output_file.open() as f:
                lines = f.readlines()

            probed_hosts = []
            for line in lines:
                if line.strip():
                    try:
                        probed_hosts.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Skip malformed lines
                        continue

            # Cleanup
            input_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)

        except (OSError, Exception) as e:
            # Cleanup on error
            if input_file.exists():
                input_file.unlink(missing_ok=True)
            if output_file.exists():
                output_file.unlink(missing_ok=True)
            return {
                "success": False,
                "error": f"Failed to run/parse httpx: {e}",
            }

        return {
            "success": True,
            "probed_hosts": probed_hosts,
        }

    def _format_results(
        self,
        domain: str,
        subdomains: list[str],
        probed_hosts: list[dict[str, Any]],
        output_format: str,
        include_inactive: bool,
    ) -> dict[str, Any]:
        """Format results based on requested output level."""

        active_hosts = [h for h in probed_hosts if h.get("status_code")]

        base_result = {
            "success": True,
            "domain": domain,
            "subdomains_discovered": len(subdomains),
            "active_hosts": len(active_hosts),
        }

        if output_format == "summary":
            # Token-efficient summary
            return {
                **base_result,
                "active_urls": [h.get("url", "") for h in active_hosts[:50]],  # Limit to 50
                "status_breakdown": self._get_status_breakdown(active_hosts),
            }

        if output_format == "detailed":
            # More details but still structured
            return {
                **base_result,
                "hosts": [
                    {
                        "url": h.get("url", ""),
                        "status_code": h.get("status_code"),
                        "title": h.get("title", "")[:100],  # Truncate titles
                        "content_length": h.get("content_length"),
                        "technologies": h.get("tech", h.get("technologies", [])),
                    }
                    for h in active_hosts[:100]  # Limit to 100
                ],
                "status_breakdown": self._get_status_breakdown(active_hosts),
                "technology_summary": self._get_tech_summary(active_hosts),
            }

        # "full"
        # Complete data (use sparingly - can be large)
        hosts_to_include = active_hosts if not include_inactive else probed_hosts
        return {
            **base_result,
            "hosts": hosts_to_include[:200],  # Hard limit to prevent token explosion
            "inactive_subdomains": (
                [s for s in subdomains if not any(h.get("host") == s for h in active_hosts)]
                if include_inactive
                else None
            ),
        }

    def _get_status_breakdown(self, hosts: list[dict[str, Any]]) -> dict[str, int]:
        """Count hosts by status code."""
        breakdown: dict[str, int] = {}
        for host in hosts:
            code = host.get("status_code", "unknown")
            breakdown[str(code)] = breakdown.get(str(code), 0) + 1
        return breakdown

    def _get_tech_summary(self, hosts: list[dict[str, Any]]) -> dict[str, int]:
        """Count technologies detected."""
        tech_counts: dict[str, int] = {}
        for host in hosts:
            # Try both 'tech' and 'technologies' keys
            techs = host.get("tech", host.get("technologies", []))
            for tech in techs:
                tech_counts[tech] = tech_counts.get(tech, 0) + 1
        # Return top 20 technologies sorted by count
        return dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:20])
