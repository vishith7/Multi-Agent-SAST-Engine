import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import os
import sys
import subprocess

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cli import handle_github_repo

class TestGitHubImport(unittest.TestCase):
    @patch('cli.shutil.which')
    def test_url_detection_and_matching(self, mock_which):
        mock_which.return_value = "git"
        
        valid_urls = [
            "https://github.com/user/repo",
            "http://github.com/user/repo",
            "https://github.com/user/repo.git",
            "git@github.com:user/repo.git",
            "ssh://git@github.com/user/repo.git",
            "https://github.com/user/repo/",
            "https://www.github.com/user/repo",
            "https://www.github.com/user/repo.git/"
        ]
        
        # We patch subprocess.run to avoid actual execution
        with patch('cli.subprocess.run') as mock_run:
            # Mock path checks
            with patch('cli.Path.exists') as mock_exists:
                mock_exists.return_value = False
                for url in valid_urls:
                    mock_run.reset_mock()
                    res = handle_github_repo(url)
                    # Should attempt to clone
                    mock_run.assert_any_call(
                        ["git", "clone", url.strip(), str(Path(res).resolve())],
                        check=True
                    )

    def test_invalid_inputs_returned_unchanged(self):
        invalid_urls = [
            "https://example.com/user/repo",
            "github.com/user/repo",
            "https://github.com/",
            "https://github.com/user",
            "https://github.com/../repo",
            "https://github.com/user/../../repo"
        ]
        for url in invalid_urls:
            res = handle_github_repo(url)
            self.assertEqual(res, url, f"Expected {url} to be returned unchanged, but got {res}")

    def test_local_paths_returned_unchanged(self):
        local_paths = [
            r"C:\Users\thane\github.com\my-local-project",
            "./repo",
            "../repo",
            ".",
            "project"
        ]
        for path in local_paths:
            res = handle_github_repo(path)
            self.assertEqual(res, path, f"Expected path {path} to be returned unchanged, but got {res}")

    @patch('cli.shutil.which')
    @patch('cli.subprocess.run')
    @patch('cli.Path.exists')
    def test_clone_behavior(self, mock_exists, mock_run, mock_which):
        mock_which.return_value = "git"
        mock_exists.return_value = False # repo doesn't exist
        
        url = "https://github.com/user/repo"
        res_path = handle_github_repo(url)
        
        # Verify it tries to clone
        dest_path = str(Path(res_path).resolve())
        mock_run.assert_called_once_with(
            ["git", "clone", url, dest_path],
            check=True
        )

    @patch('cli.shutil.which')
    @patch('cli.subprocess.run')
    @patch('cli.Path.exists')
    def test_pull_behavior_when_valid_git_repo(self, mock_exists, mock_run, mock_which):
        mock_which.return_value = "git"
        mock_exists.return_value = True # repo exists
        
        # Mock rev-parse to succeed (valid work tree)
        mock_run.return_value = MagicMock(returncode=0)
        
        url = "https://github.com/user/repo"
        res_path = handle_github_repo(url)
        
        # Verify it checks if inside work tree, and calls pull
        dest_path = str(Path(res_path).resolve())
        mock_run.assert_any_call(
            ["git", "-C", dest_path, "rev-parse", "--is-inside-work-tree"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        mock_run.assert_any_call(
            ["git", "-C", dest_path, "pull"],
            check=True
        )

    @patch('cli.shutil.which')
    @patch('cli.subprocess.run')
    @patch('cli.Path.exists')
    def test_invalid_existing_destination_raises_error(self, mock_exists, mock_run, mock_which):
        mock_which.return_value = "git"
        mock_exists.return_value = True # directory exists
        
        # Mock rev-parse to fail (indicating it is not a valid git repository)
        import subprocess as sp
        mock_run.side_effect = sp.CalledProcessError(1, "git rev-parse")
        
        url = "https://github.com/user/repo"
        with self.assertRaises(RuntimeError) as ctx:
            handle_github_repo(url)
            
        self.assertIn("The clone destination already exists but is not a valid Git repository", str(ctx.exception))

    @patch('cli.shutil.which')
    def test_git_unavailable_raises_error(self, mock_which):
        mock_which.return_value = None # git is missing
        
        url = "https://github.com/user/repo"
        with self.assertRaises(RuntimeError) as ctx:
            handle_github_repo(url)
            
        self.assertIn("Git is not installed or is not available in PATH", str(ctx.exception))

    @patch('cli.shutil.which')
    @patch('cli.subprocess.run')
    @patch('cli.Path.exists')
    def test_collision_behavior(self, mock_exists, mock_run, mock_which):
        mock_which.return_value = "git"
        mock_exists.return_value = False
        
        url_a = "https://github.com/userA/tool"
        url_b = "https://github.com/userB/tool"
        
        res_a = handle_github_repo(url_a)
        res_b = handle_github_repo(url_b)
        
        # Verify paths are distinct and include owner name
        self.assertNotEqual(res_a, res_b)
        self.assertTrue("userA" in res_a)
        self.assertTrue("userB" in res_b)
        self.assertTrue("tool" in res_a)
        self.assertTrue("tool" in res_b)

if __name__ == '__main__':
    unittest.main()
