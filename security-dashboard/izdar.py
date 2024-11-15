import os
import re
import fnmatch
import sys
from pathlib import Path

def normalize_path(path):
    """Normalize path to use forward slashes"""
    return path.replace(os.sep, '/')

def parse_ignore_file(ignore_file):
    """Parse .gitignore or .dirignore file and return list of patterns"""
    patterns = []
    if os.path.exists(ignore_file):
        try:
            with open(ignore_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        except Exception as e:
            print(f"Warning: Error reading {ignore_file}: {e}", file=sys.stderr)
    return patterns

def get_ignore_patterns(directory):
    """Get combined ignore patterns from .gitignore and .dirignore in the given directory"""
    patterns = []
    
    # Check for .gitignore
    gitignore_path = os.path.join(directory, '.gitignore')
    patterns.extend(parse_ignore_file(gitignore_path))
    
    # Check for .dirignore
    dirignore_path = os.path.join(directory, '.dirignore')
    patterns.extend(parse_ignore_file(dirignore_path))
    
    return [pattern_to_regex(p) for p in patterns if p]

def pattern_to_regex(pattern):
    """Convert ignore pattern to regex"""
    if not pattern or pattern.startswith('#'):
        return None
        
    # Handle negation
    negative = pattern.startswith('!')
    if negative:
        pattern = pattern[1:]
    
    # Strip leading and trailing whitespace and slashes
    pattern = pattern.strip().strip('/')
    
    # Convert glob pattern to regex
    regex = pattern.replace('.', r'\.')
    regex = regex.replace('**', '.*')
    regex = regex.replace('*', '[^/]*')
    regex = regex.replace('?', '.')
    
    # Handle directory-only patterns
    if pattern.endswith('/'):
        regex += '.*'
    else:
        regex += '(/.*)?$'
    
    # Match from start of path or after slash
    regex = f'(^|/){regex}'
    
    return re.compile(regex)

def is_git_related(path):
    """Check if path is a git-related file or directory"""
    git_patterns = [
        '.git', 
        '.git/**', 
        '.gitignore',
        '.gitmodules',
        '.gitattributes',
        '.dirignore'  # Also ignore .dirignore files
    ]
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(name, pattern) for pattern in git_patterns)

def should_ignore(path, current_dir, base_dir, ignore_patterns_stack, script_path):
    """Determine if a path should be ignored using stacked ignore patterns"""
    if path == script_path or is_git_related(path):
        return True
        
    try:
        # Get all possible relative paths for matching
        rel_paths = [
            # Relative to current directory being processed
            normalize_path(os.path.relpath(path, current_dir)),
            '/' + normalize_path(os.path.relpath(path, current_dir)),
            # Relative to base scan directory
            normalize_path(os.path.relpath(path, base_dir)),
            '/' + normalize_path(os.path.relpath(path, base_dir)),
            # The path components themselves
            os.path.basename(path),
            normalize_path(path)  # Full path
        ]
        
        # Check against all ignore patterns in the stack
        for patterns in ignore_patterns_stack:
            for pattern in patterns:
                if pattern:
                    # Check the path against each possible relative path
                    for rel_path in rel_paths:
                        if pattern.search(rel_path):
                            return True
                    
    except Exception as e:
        print(f"Warning: Error checking ignore status for {path}: {e}", file=sys.stderr)
        return False
            
    return False

def is_binary_file(file_path):
    """Check if a file is binary"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read()
            return False
    except (UnicodeDecodeError, PermissionError):
        return True
    except Exception as e:
        print(f"Warning: Error checking if file is binary {file_path}: {e}", file=sys.stderr)
        return True

def get_file_content(file_path):
    """Get the content of a file with proper encoding"""
    if is_binary_file(file_path):
        return None
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            line_count = len(content.splitlines())
            if line_count > 500:
                print(f"Warning: Large file detected ({line_count} lines): {file_path}", file=sys.stderr)
            return content
    except PermissionError:
        print(f"Warning: Permission denied reading file: {file_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Warning: Error reading file {file_path}: {e}", file=sys.stderr)
        return None

def generate_project_documentation(root_dir, base_dir=None, current_ignore_patterns=None, prefix="", is_last=True, script_path=None, ignore_patterns_stack=None):
    """Generate project documentation including directory tree and file contents"""
    tree = []
    file_contents = []
    
    try:
        root_dir = os.path.abspath(root_dir)
        if not os.path.isdir(root_dir):
            return ["Error: Not a valid directory"], []

        # Initialize at the root level
        if base_dir is None:
            base_dir = root_dir
            ignore_patterns_stack = []
        
        # Get ignore patterns for current directory and add to stack
        current_patterns = get_ignore_patterns(root_dir)
        if current_patterns:
            ignore_patterns_stack.append(current_patterns)

        # Generate directory entry in tree
        if root_dir != base_dir:
            dir_name = os.path.basename(root_dir)
            if not is_last:
                tree.append(prefix + "├── " + dir_name)
                new_prefix = prefix + "│   "
            else:
                tree.append(prefix + "└── " + dir_name)
                new_prefix = prefix + "    "
        else:
            new_prefix = prefix

        try:
            files = os.listdir(root_dir)
        except PermissionError:
            print(f"Warning: Permission denied accessing directory: {root_dir}", file=sys.stderr)
            tree.append(prefix + "Permission denied")
            return tree, file_contents
        except Exception as e:
            print(f"Warning: Error listing directory {root_dir}: {e}", file=sys.stderr)
            return tree, file_contents

        # Filter and sort files
        files = [f for f in files if not should_ignore(
            os.path.join(root_dir, f), 
            root_dir,
            base_dir,
            ignore_patterns_stack, 
            script_path
        )]
        files = sorted(files, key=lambda f: (os.path.isfile(os.path.join(root_dir, f)), f.lower()))

        # Process each file/directory
        for i, file in enumerate(files):
            path = os.path.join(root_dir, file)
            is_last_file = (i == len(files) - 1)

            try:
                if os.path.isdir(path):
                    # Pass the current stack of ignore patterns to subdirectories
                    subtree, subcontents = generate_project_documentation(
                        path,
                        base_dir,
                        current_patterns,
                        new_prefix,
                        is_last_file,
                        script_path,
                        ignore_patterns_stack
                    )
                    tree.extend(subtree)
                    file_contents.extend(subcontents)
                else:
                    if is_last_file:
                        tree.append(new_prefix + "└── " + file)
                    else:
                        tree.append(new_prefix + "├── " + file)

                    content = get_file_content(path)
                    if content is not None:
                        rel_path = os.path.relpath(path, base_dir)
                        file_contents.append(f"\nFile: {rel_path}\n")
                        file_contents.append("-" * 80)  # Separator line
                        file_contents.append(content)
                        file_contents.append("-" * 80 + "\n")  # Separator line
            except Exception as e:
                print(f"Warning: Error processing {path}: {e}", file=sys.stderr)
                continue

        # Remove current directory's patterns from stack before returning
        if current_patterns:
            ignore_patterns_stack.pop()

    except Exception as e:
        print(f"Warning: Error in documentation generation: {e}", file=sys.stderr)
        return tree, file_contents

    return tree, file_contents

def main():
    # Get the directory to scan (current directory if not specified)
    scan_directory = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    
    # Get the script's directory for output file location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.abspath(__file__)
    
    # Set output file path in the same directory as the script
    output_file = os.path.join(script_dir, "project_documentation.txt")
    
    print("Starting project documentation generation...")
    print(f"Scanning directory: {scan_directory}")
    print("Files over 500 lines will be logged below:")
    print("-" * 60)
    
    # Remove existing file if it exists
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except Exception as e:
            print(f"Warning: Could not remove existing documentation file: {e}", file=sys.stderr)
    
    try:
        # Generate documentation scanning from the specified/current directory
        tree, file_contents = generate_project_documentation(scan_directory, script_path=script_path)
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8', buffering=1) as f:
            f.truncate(0)
            f.write("Project Documentation\n")
            f.write("===================\n\n")
            f.write("Directory Structure\n")
            f.write("------------------\n\n")
            f.write("\n".join(tree))
            f.write("\n\n")
            f.write("File Contents\n")
            f.write("-------------\n")
            f.write("\n".join(file_contents))
            
        print("-" * 60)
        print(f"Documentation generated successfully in {output_file}")
        
    except Exception as e:
        print(f"Error generating documentation: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()