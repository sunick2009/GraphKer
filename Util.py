import os
import platform
import shutil
import sys
from loguru import logger

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
            logger.warning(f"Could not load .env file at {path}: {e}")

    @staticmethod
    def setup_logger():
        """Configure loguru once for the application."""
        logger.remove()
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        logger.add(sys.stdout, level=log_level, format="[{time:YYYY-MM-DD HH:mm:ss}] {level:<8} {message}")

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
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
                logger.info(f"Created import directory: {path}")
                return

            # List all files and directories inside the specified directory
            directory_contents = os.listdir(path)

            # Delete each file and subdirectory within the directory
            for item in directory_contents:
                item_path = os.path.join(path, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)

            logger.info(f"Contents of '{path}' have been deleted.")
        except FileNotFoundError:
            logger.warning(f"Directory not found: {path}")
        except Exception as e:
            logger.error(f"Error occurred while clearing directory {path}: {e}")
    
    # Set Import Directory
    def set_import_path(directory):
        if not directory:
            raise ValueError("Import path is required.")

        current_os = platform.system()
        if current_os in ("Linux", "Darwin"):
            return os.path.abspath(directory)
        elif current_os == "Windows":
            normalized = directory.replace("\\", "\\\\")
            return os.path.abspath(normalized) + "\\\\"


    # Copy Cypher Script Schema Files to Import Path
    def copy_files_cypher_script(to_path):
        current_path = os.path.join(os.getcwd(), "CypherScripts")
        if not os.path.isdir(current_path):
            logger.error(f"CypherScripts directory not found at {current_path}")
            return

        os.makedirs(to_path, exist_ok=True)
        for name in os.listdir(current_path):
            if name.endswith(".cypher"):
                src = os.path.join(current_path, name)
                dst = os.path.join(to_path, name)
                shutil.copy2(src, dst)
                logger.debug(f"Copied Cypher script {name} to import path")
