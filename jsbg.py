import requests, os, time, subprocess
from zipfile import ZipFile

java_version = "22"

def generate(app_name):
    print(f"Generating {app_name}...")
    url = "https://start.spring.io/starter.zip"
    params = {
        "name": app_name,
        "groupId": f"com.app_name",
        "artifactId": app_name,
        "javaVersion": java_version,
        "dependencies": "web,data-jpa,validation,thymeleaf,mail,postgresql,flyway,actuator",
    }

    # Make POST request with form data
    response = requests.post(url, data=params)

    # Save the zip file
    if response.status_code == 200:
        with open(f"{app_name}.zip", "wb") as f:
            f.write(response.content)
        print(f"✅ Project generated: {app_name}.zip")
    else:
        print(f"❌ Failed: {response.status_code} {response.text}")

    # Unzip the file
    with open(f"{app_name}.zip", "rb") as f:
        with ZipFile(f) as zip:
            zip.extractall()

    print(f"✅ Unzipped: {app_name}")

    # Delete the zip file
    os.remove(f"{app_name}.zip")
    print(f"✅ Deleted: {app_name}.zip")


def install(app_name):
    # Move to the project directory
    os.chdir(app_name)
    print(f"✅ Moved to: {app_name}")

    # Run Maven install
    os.system("mvn clean install")
    print("✅ Maven install")

    # Run the application
    os.system("mvn spring-boot:run")
    print("✅ Application running")

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def timestamp_12hour():
    return time.strftime("%Y-%m-%d %I:%M %p", time.localtime())

def short_date():
    return time.strftime("%Y-%m-%d", time.localtime())

def log(msg):
    dir = "logs"
    if not os.path.exists(dir):
        os.makedirs(dir)

    with open(os.path.join(dir, f"{timestamp_12hour()} - {short_date()}.log"), "a") as f:
        f.write(f"{timestamp()}\n\n{msg}\n\n")

def test():
    request_url = [
        "http://localhost:8080", 
        "http://localhost:8080/hello", 
        "http://localhost:8080/actuator/health", 
        "http://localhost:8080/actuator/metrics",
        "http://localhost:8080/actuator/prometheus", 
        "http://localhost:8080/actuator/heapdump", 
        "http://localhost:8080/actuator/threaddump", 
        "http://localhost:8080/actuator/loggers",
        "http://localhost:8080/actuator/heapdump"
    ]

    for url in request_url:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"✅ link: {url} works")
        else:
            print(f"❌ link: {url} does not work")
            log(url)
            continue

def is_docker_installed() -> bool:
    try:
        subprocess.check_output(["docker", "--version"])
        return True
    except FileNotFoundError:
        return False

def install_needed_tools() -> None:
    if not is_docker_installed():
        os.system("brew install --cask docker")
        print("✅ Docker installed")
    else:
        print("✅ Docker already installed")

    os.system("brew install openjdk@22")
    os.system("brew install maven")
    os.system("pip install -r requirements.txt")
    

def main():
    app_name = input("Enter the application name: ")
    uri_test = input("Do you want to test the application? (y/n): ")
    print(f"Generating {app_name}...")
    
    generate(app_name)
    install(app_name)

    match uri_test.lower():
        case "y" | "yes" | "true" | "1" | "t" | "yeah" | "yup" | "yep":
            test()
        case "n" | "no" | "false" | "0" | "f" | "nope" | "nup" | "nep":
            print("✅ Application generated")
        case _:
            print("Invalid input")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
