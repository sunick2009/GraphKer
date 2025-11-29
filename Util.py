import os
import platform
import shutil

class Util:
    @staticmethod
    def load_env_file(path: str = ".env"):
        """Load simple KEY=VALUE pairs from a .env file into os.environ."""
        if not os.path.exists(path):
            return
        try:
            with open(path, "r") as env_file:
                for line in env_file:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if "=" not in stripped:
                        continue
                    key, value = stripped.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('\'"')
                    if key and key not in os.environ:
                        os.environ[key] = value
        except OSError as e:
            print(f"Warning: could not load .env file at {path}: {e}")

    @staticmethod
    def replace_placeholder_with_value(line, files_by_type):
        for key in files_by_type.keys():
            if key in line:
                return line.replace(key, Util.string_to_insert_from_files(files_by_type[key]))
        return line

    @staticmethod
    def string_to_insert_from_files(files):
        stringToInsert = "\""
        for file in files:
            stringToInsert += file + "\", \""
        stringToInsert = stringToInsert[:-3]
        return stringToInsert
    
    # Clear Import Directory
    def clear_directory(path):
        try:
            # List all files and directories inside the specified directory
            directory_contents = os.listdir(path)

            # Delete each file and subdirectory within the directory
            for item in directory_contents:
                item_path = os.path.join(path, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)

            print(f"Contents of '{path}' have been deleted.")
        except FileNotFoundError:
            print(f"Directory not found: {path}")
        except Exception as e:
            print(f"Error occurred: {e}")
    
    # Set Import Directory
    def set_import_path(directory):
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            return directory
        elif current_os == "Windows":
            return directory.replace("\\", "\\\\") + "\\\\"


    # Copy Cypher Script Schema Files to Import Path
    def copy_files_cypher_script(to_path):
        current_path = os.getcwd()
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            current_path += "/CypherScripts/"
        elif current_os == "Windows":
            current_path += "\CypherScripts\\"

        shutil.copy2(current_path + "ConstraintsIndexes.cypher", to_path)
        shutil.copy2(current_path + "ClearConstraintsIndexes.cypher", to_path)