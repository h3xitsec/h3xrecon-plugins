from hatchling.metadata.plugin.interface import MetadataHookInterface
from pathlib import Path
from typing import Any, Dict
import os

class VersionReplacementHook(MetadataHookInterface):
    def update(self, metadata: Dict[str, Any]) -> None:
        """
        Update the metadata with version replacements
        """
        about = {}
        # Try multiple possible locations for the about file
        possible_paths = [
            Path(self.root) / "src" / "h3xrecon_plugins" / "__about__.py",
            Path(self.root) / "h3xrecon_plugins" / "__about__.py",
        ]
        
        about_path = None
        for path in possible_paths:
            print(f"Checking path: {path}")
            if path.exists():
                about_path = path
                break
                
        if about_path is None:
            raise FileNotFoundError(f"Could not find __about__.py in any of: {possible_paths}")
            
        print(f"Using about.py from: {about_path}")
        
        with about_path.open("r") as f:
            exec(f.read(), about)
        
        if "dependencies" in metadata:
            dependencies = metadata["dependencies"]
            
            for i, dep in enumerate(dependencies):
                if "___COREVERSION___" in dep:
                    dependencies[i] = dep.replace("___COREVERSION___", about["__core_version__"])            
            metadata["dependencies"] = dependencies

if __name__ == "__main__":
    # Test config that mimics your pyproject.toml structure
    test_config = {
        "project": {
            "dependencies": [
                "h3xrecon-core==___COREVERSION___",
            ]
        }
    }
    
    # Run the function and print results
    result = VersionReplacementHook(test_config)
    print("Modified config:")
    print(result.metadata)