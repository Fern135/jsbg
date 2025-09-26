#!/usr/bin/env python3
import argparse, requests, os, time, subprocess, sys, shutil, platform
from zipfile import ZipFile
from pathlib import Path

java_version = "22"

def generate(app_name, group_id=None, deps=None, outdir=None, keep_zip=False):
    print(f"Generating {app_name}...")
    url = "https://start.spring.io/starter.zip"
    params = {
        "name": app_name,
        "groupId": group_id or f"com.{app_name.lower()}",
        "artifactId": app_name,
        "javaVersion": java_version,
        "dependencies": deps or "web,data-jpa,validation,thymeleaf,mail,postgresql,flyway,actuator",
    }

    # Make POST request with form data
    try:
        response = requests.post(url, data=params, timeout=60)
    except requests.RequestException as e:
        print(f"❌ Network error: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"❌ Failed: {response.status_code} {response.text[:300]}")
        sys.exit(1)

    zip_path = Path(f"{app_name}.zip")
    zip_path.write_bytes(response.content)
    print(f"✅ Project generated: {zip_path.name}")

    # Unzip to target dir (default: ./<app_name>)
    target = Path(outdir or app_name)
    target.mkdir(parents=True, exist_ok=True)
    with ZipFile(zip_path) as z:
        z.extractall(target)
    print(f"✅ Unzipped to: {target.resolve()}")

    if not keep_zip:
        zip_path.unlink(missing_ok=True)
        print(f"✅ Deleted: {app_name}.zip")

def install(app_name):
    os.chdir(app_name)
    print(f"✅ Moved to: {Path.cwd()}")
    rc = os.system("mvn -q -DskipTests clean install")
    if rc != 0:
        print("❌ Maven build failed"); sys.exit(rc)
    print("✅ Maven install")
    rc = os.system("mvn -q spring-boot:run")
    sys.exit(rc)

def timestamp(): 
    return time.strftime("%Y-%m-%d %H-%M-%S", time.localtime())  # no colon for Windows

def short_date(): 
    return time.strftime("%Y-%m-%d", time.localtime())

def log(msg):
    d = Path("logs"); d.mkdir(exist_ok=True)
    fname = d / f"{short_date()}_{timestamp()}.log"
    fname.write_text(f"{timestamp()}\n\n{msg}\n\n", encoding="utf-8")

def test(base="http://localhost:8080"):
    # Probe only endpoints likely enabled by default
    request_urls = [
        base,
        f"{base}/actuator/health",
    ]
    for url in request_urls:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(f"✅ {url} works")
            else:
                print(f"❌ {url} -> {r.status_code}")
        except Exception as e:
            print(f"❌ {url} -> {e}")
            log(f"{url} -> {e}")

def have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run_sudo(cmd: list[str]) -> int:
    # Use sudo on Unix if not root; on Windows just run
    if platform.system().lower() in ("linux", "darwin"):
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
    return subprocess.call(cmd)

def setup_tools():
    """
    Best-effort installer for Java 22 + Maven + pip requests.
    We try common package managers and print fallbacks when needed.
    """
    system = platform.system().lower()
    print(f"Detected OS: {system}")

    # Ensure Python requests
    try:
        import requests as _  # noqa
        print("✅ Python 'requests' installed")
    except Exception:
        print("Installing Python 'requests'…")
        rc = subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "requests"])
        if rc != 0:
            print("❌ Failed to install 'requests'. Install manually: pip install requests")
        else:
            print("✅ Installed 'requests'")

    # Java + Maven
    if system == "darwin":
        # Homebrew
        if not have_cmd("brew"):
            print("❌ Homebrew not found. Install from https://brew.sh/")
        else:
            # Prefer temurin@22 cask; fallback to openjdk@22 formula
            if not have_cmd("java"):
                print("Installing Temurin/OpenJDK 22 via Homebrew…")
                rc = run_sudo(["brew", "install", "--cask", "temurin@22"])
                
                if rc != 0:
                    rc = run_sudo(["brew", "install", "openjdk@22"])
                if rc == 0:
                    print("✅ JDK 22 installed (you may need to add it to PATH)")
                    return
                else:
                    print("❌ Could not install JDK 22. See https://adoptium.net/")
                    return

            else:
                print("✅ Java already present")

            if not have_cmd("mvn"):
                print("Installing Maven via Homebrew…")
                rc = run_sudo(["brew", "install", "maven"])
                print("✅ Maven installed" if rc == 0 else "❌ Maven install failed")
                return

            else:
                print("✅ Maven already present")

    elif system == "windows":
        # Winget preferred; fallback choco
        if not have_cmd("java"):
            if have_cmd("winget"):
                print("Installing Temurin 22 JDK via winget…")
                rc = subprocess.call(["winget", "install", "--id", "EclipseAdoptium.Temurin.22.JDK", "-e", "--source", "winget"])
                print("✅ JDK 22 installed" if rc == 0 else "❌ JDK install failed via winget")
                return

            elif have_cmd("choco"):
                print("Installing Temurin 22 JDK via Chocolatey…")
                rc = run_sudo(["choco", "install", "-y", "temurin22"])
                print("✅ JDK 22 installed" if rc == 0 else "❌ JDK install failed via choco")
                return

            else:
                print("❌ No winget/choco. Install JDK 22 manually: https://adoptium.net/")
                return
                
        else:
            print("✅ Java already present")

        if not have_cmd("mvn"):
            if have_cmd("winget"):
                print("Installing Maven via winget…")
                rc = subprocess.call(["winget", "install", "--id", "Apache.Maven", "-e", "--source", "winget"])
                print("✅ Maven installed" if rc == 0 else "❌ Maven install failed via winget")
                return
                
            elif have_cmd("choco"):
                print("Installing Maven via Chocolatey…")
                rc = run_sudo(["choco", "install", "-y", "maven"])
                print("✅ Maven installed" if rc == 0 else "❌ Maven install failed via choco")
                return

            else:
                print("❌ No winget/choco. Install Maven manually: https://maven.apache.org/download.cgi")
                return
        else:
            print("✅ Maven already present")

    else:
        # Linux
        pkg_cmd = None
        if have_cmd("apt"):
            pkg_cmd = "apt"
        elif have_cmd("apt-get"):
            pkg_cmd = "apt-get"
        elif have_cmd("dnf"):
            pkg_cmd = "dnf"
        elif have_cmd("yum"):
            pkg_cmd = "yum"
        elif have_cmd("pacman"):
            pkg_cmd = "pacman"

        # JDK 22 names vary; try common ones, then print manual fallback.
        if not have_cmd("java"):
            print("Installing JDK 22 (best effort)…")
            rc = 1
            if pkg_cmd in ("apt", "apt-get"):
                rc = run_sudo([pkg_cmd, "update"]) or run_sudo([pkg_cmd, "install", "-y", "openjdk-22-jdk"])
                if rc != 0:
                    print("⚠️ Couldn’t install JDK 22 via your package manager.")
                    print("Install manually from Adoptium: https://adoptium.net/temurin/releases/?version=22")
                    return
                    
            elif pkg_cmd in ("dnf", "yum"):
                # Fedora/RHEL may have java-22-openjdk-devel
                rc = run_sudo([pkg_cmd, "install", "-y", "java-22-openjdk-devel"])
                if rc != 0:
                    rc = run_sudo([pkg_cmd, "install", "-y", "java-22-openjdk"])
            elif pkg_cmd == "pacman":
                rc = run_sudo(["pacman", "-Sy", "--noconfirm", "jdk-openjdk"])

            if rc != 0:
                print("⚠️ Couldn’t install JDK 22 via your package manager.")
                print("Install manually from Adoptium: https://adoptium.net/temurin/releases/?version=22")
                return

            else:
                print("✅ JDK installed")
        else:
            print("✅ Java already present")

        if not have_cmd("mvn"):
            print("Installing Maven…")
            rc = 1
            if pkg_cmd in ("apt", "apt-get"):
                rc = run_sudo([pkg_cmd, "install", "-y", "maven"])
            elif pkg_cmd in ("dnf", "yum"):
                rc = run_sudo([pkg_cmd, "install", "-y", "maven"])
            elif pkg_cmd == "pacman":
                rc = run_sudo(["pacman", "-Sy", "--noconfirm", "maven"])
            print("✅ Maven installed" if rc == 0 else "⚠️ Couldn’t install Maven; install manually.")
        else:
            print("✅ Maven already present")

    print("✅ Setup complete (or best effort). If Java isn’t 22, adjust PATH/JAVA_HOME accordingly.")

def main():
    p = argparse.ArgumentParser(prog="jsbg", description="Spring Boot generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("new", help="Generate a new project from start.spring.io")
    g.add_argument("name")
    g.add_argument("--group-id", default=None, help="Override groupId (default: com.<name>)")
    g.add_argument("--deps", default=None, help="Comma-separated dependencies")
    g.add_argument("--outdir", default=None, help="Directory to unzip into (default: ./<name>)")
    g.add_argument("--keep-zip", action="store_true", help="Keep the downloaded zip")

    i = sub.add_parser("install", help="Build and run with Maven")
    i.add_argument("name", help="Directory name you generated (artifactId)")

    t = sub.add_parser("test", help="Check basic endpoints")
    t.add_argument("--base", default="http://localhost:8080", help="Base URL to test")

    sub.add_parser("doctor", help="Show what tools are needed and versions if present")
    sub.add_parser("setup-tools", help="Attempt to install Java 22 + Maven + requests for this OS")

    args = p.parse_args()

    if not args.cmd:
        p.print_help()
        sys.exit(2)

    if args.cmd == "doctor":
        print("Needs: Java 22 (JDK), Maven, Python 'requests'")
        print(f"java in PATH?  {'yes' if have_cmd('java') else 'no'}")
        print(f"mvn in PATH?   {'yes' if have_cmd('mvn') else 'no'}")
        print(f"pip present?   {'yes' if have_cmd('pip') else 'no'}")
        return

    if args.cmd == "setup-tools":
        setup_tools()
        return

    if args.cmd == "new":
        generate(args.name, group_id=args.group_id, deps=args.deps, outdir=args.outdir, keep_zip=args.keep_zip)
        return

    if args.cmd == "install":
        install(args.name)
        return

    if args.cmd == "test":
        test(args.base)
        return

if __name__ == "__main__":
    main()
