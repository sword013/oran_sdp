import subprocess

def print_menu():
    print("\n--- Docker Container Manager ---")
    print("1. Start a container")
    print("2. Stop a container")
    print("3. Enter into a container")
    print("4. List running containers")
    print("5. List all containers")
    print("6. Remove a container")
    print("7. Delete a container (stop and remove)")
    print("8. Exit")

def start_container():
    image_name = input("Enter the Docker image name: ")
    container_name = input("Enter a name for the container (optional, press Enter to skip): ")
    port_mapping = input("Enter port mapping (e.g., 3000:3000, optional, press Enter to skip): ")

    command = ["docker", "run", "-d"]
    if container_name:
        command.extend(["--name", container_name])
    if port_mapping:
        command.extend(["-p", port_mapping])
    command.append(image_name)

    try:
        subprocess.run(command, check=True)
        print(f"Container started successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to start container: {e}")

def stop_container():
    container_id = input("Enter the container ID or name: ")
    try:
        subprocess.run(["docker", "stop", container_id], check=True)
        print(f"Container {container_id} stopped successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to stop container: {e}")

def enter_container():
    container_id = input("Enter the container ID or name: ")
    try:
        subprocess.run(["docker", "exec", "-it", container_id, "/bin/bash"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to enter container: {e}")

def list_running_containers():
    try:
        subprocess.run(["docker", "ps"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to list running containers: {e}")

def list_all_containers():
    try:
        subprocess.run(["docker", "ps", "-a"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to list all containers: {e}")

def remove_container():
    container_id = input("Enter the container ID or name: ")
    try:
        subprocess.run(["docker", "rm", container_id], check=True)
        print(f"Container {container_id} removed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove container: {e}")

def delete_container():
    container_id = input("Enter the container ID or name: ")
    try:
        # Stop the container
        subprocess.run(["docker", "stop", container_id], check=True)
        print(f"Container {container_id} stopped successfully!")
        
        # Remove the container
        subprocess.run(["docker", "rm", container_id], check=True)
        print(f"Container {container_id} removed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete container: {e}")

def main():
    while True:
        print_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            start_container()
        elif choice == "2":
            stop_container()
        elif choice == "3":
            enter_container()
        elif choice == "4":
            list_running_containers()
        elif choice == "5":
            list_all_containers()
        elif choice == "6":
            remove_container()
        elif choice == "7":
            delete_container()
        elif choice == "8":
            print("Exiting Docker Container Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
