#!/usr/bin/env python3
"""
Unit tests for NordVPN WireGuard Configuration Generator
"""

import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
import json
import tempfile
import os
from pathlib import Path
import requests

# Import the classes to test
from nordvpn_wireguard_generator import NordVPNWireGuardGenerator
from config_manager import ConfigManager


class TestNordVPNWireGuardGenerator(unittest.TestCase):
    
    def setUp(self):
        self.generator = NordVPNWireGuardGenerator()
        self.sample_server = {
            'hostname': 'us1234.nordvpn.com',
            'station': '192.168.1.100',
            'load': 25,
            'locations': [{'country': {'name': 'United States', 'code': 'US'}}],
            'technologies': [{'identifier': 'wireguard_udp'}]
        }
        self.sample_countries = [
            {'code': 'US', 'name': 'United States'},
            {'code': 'UK', 'name': 'United Kingdom'},
            {'code': 'DE', 'name': 'Germany'}
        ]
    
    @patch('requests.get')
    def test_get_servers_success(self, mock_get):
        """Test successful server retrieval"""
        mock_response = Mock()
        mock_response.json.return_value = [self.sample_server]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        servers = self.generator.get_servers(country='US', limit=5)
        
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]['hostname'], 'us1234.nordvpn.com')
        mock_get.assert_called_once()
        
        # Verify correct API parameters
        call_args = mock_get.call_args
        self.assertIn('filters[country_code]', call_args[1]['params'])
        self.assertEqual(call_args[1]['params']['filters[country_code]'], 'US')
        self.assertEqual(call_args[1]['params']['limit'], 5)
    
    @patch('requests.get')
    def test_get_servers_no_country_filter(self, mock_get):
        """Test server retrieval without country filter"""
        mock_response = Mock()
        mock_response.json.return_value = [self.sample_server]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        servers = self.generator.get_servers(limit=10)
        
        call_args = mock_get.call_args
        self.assertNotIn('filters[country_code]', call_args[1]['params'])
        self.assertEqual(call_args[1]['params']['limit'], 10)
    
    @patch('requests.get')
    def test_get_servers_request_exception(self, mock_get):
        """Test server retrieval with network error"""
        mock_get.side_effect = requests.RequestException("Network error")
        
        servers = self.generator.get_servers()
        
        self.assertEqual(servers, [])
    
    @patch('requests.get')
    def test_get_countries_success(self, mock_get):
        """Test successful countries retrieval"""
        mock_response = Mock()
        mock_response.json.return_value = self.sample_countries
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        countries = self.generator.get_countries()
        
        self.assertEqual(len(countries), 3)
        self.assertEqual(countries[0]['code'], 'US')
        mock_get.assert_called_once_with(f"{self.generator.api_base}/v1/servers/countries")
    
    @patch('requests.get')
    def test_get_countries_request_exception(self, mock_get):
        """Test countries retrieval with network error"""
        mock_get.side_effect = requests.RequestException("API error")
        
        countries = self.generator.get_countries()
        
        self.assertEqual(countries, [])
    
    @patch('subprocess.check_output')
    def test_generate_keys_success(self, mock_subprocess):
        """Test successful key generation"""
        mock_subprocess.side_effect = [
            'private_key_here\n',  # First call for private key
            'public_key_here\n'    # Second call for public key
        ]
        
        private_key, public_key = self.generator.generate_keys()
        
        self.assertEqual(private_key, 'private_key_here')
        self.assertEqual(public_key, 'public_key_here')
        self.assertEqual(mock_subprocess.call_count, 2)
    
    @patch('subprocess.check_output')
    def test_generate_keys_subprocess_error(self, mock_subprocess):
        """Test key generation with subprocess error"""
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'wg')
        
        with self.assertRaises(SystemExit):
            self.generator.generate_keys()
    
    @patch('subprocess.check_output')
    def test_generate_keys_file_not_found(self, mock_subprocess):
        """Test key generation when WireGuard not installed"""
        mock_subprocess.side_effect = FileNotFoundError()
        
        with self.assertRaises(SystemExit):
            self.generator.generate_keys()
    
    def test_create_config_success(self):
        """Test successful configuration creation"""
        private_key = "test_private_key"
        dns = "1.1.1.1,8.8.8.8"
        
        config = self.generator.create_config(self.sample_server, private_key, dns)
        
        self.assertIn(private_key, config)
        self.assertIn(dns, config)
        self.assertIn(self.sample_server['station'], config)
        self.assertIn(self.generator.nordlynx_public_key, config)
        self.assertIn("10.5.0.2/32", config)
        self.assertIn("51820", config)
    
    def test_create_config_no_wireguard_tech(self):
        """Test configuration creation with server missing WireGuard support"""
        server_no_wg = {
            'hostname': 'test.nordvpn.com',
            'station': '192.168.1.100',
            'technologies': [{'identifier': 'openvpn_udp'}]  # No WireGuard
        }
        
        with self.assertRaises(ValueError) as context:
            self.generator.create_config(server_no_wg, "test_key")
        
        self.assertIn("No WireGuard endpoint found", str(context.exception))
    
    def test_create_config_empty_technologies(self):
        """Test configuration creation with server having no technologies"""
        server_no_tech = {
            'hostname': 'test.nordvpn.com',
            'station': '192.168.1.100',
            'technologies': []
        }
        
        with self.assertRaises(ValueError):
            self.generator.create_config(server_no_tech, "test_key")
    
    @patch('pathlib.Path.write_text')
    def test_save_config(self, mock_write_text):
        """Test configuration file saving"""
        config_content = "[Interface]\nPrivateKey = test"
        filename = "test.conf"
        
        self.generator.save_config(config_content, filename)
        
        mock_write_text.assert_called_once_with(config_content)
    
    @patch('nordvpn_wireguard_generator.NordVPNWireGuardGenerator.get_countries')
    @patch('builtins.print')
    def test_list_countries_success(self, mock_print, mock_get_countries):
        """Test listing countries successfully"""
        mock_get_countries.return_value = self.sample_countries
        
        self.generator.list_countries()
        
        # Verify print was called with country information
        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertTrue(any("Available countries:" in call for call in print_calls))
        self.assertTrue(any("US: United States" in call for call in print_calls))
    
    @patch('nordvpn_wireguard_generator.NordVPNWireGuardGenerator.get_countries')
    @patch('builtins.print')
    def test_list_countries_failure(self, mock_print, mock_get_countries):
        """Test listing countries with API failure"""
        mock_get_countries.return_value = []
        
        self.generator.list_countries()
        
        mock_print.assert_called_with("Failed to fetch countries list")


class TestConfigManager(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ConfigManager(self.temp_dir)
        
        # Create sample config files
        self.config1_path = Path(self.temp_dir) / "server1.conf"
        self.config2_path = Path(self.temp_dir) / "server2.conf"
        self.config1_path.write_text("[Interface]\nPrivateKey = key1")
        self.config2_path.write_text("[Interface]\nPrivateKey = key2")
    
    def tearDown(self):
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_list_configs(self):
        """Test listing available configurations"""
        configs = self.manager.list_configs()
        
        self.assertEqual(len(configs), 2)
        self.assertIn("server1", configs)
        self.assertIn("server2", configs)
        self.assertEqual(configs, sorted(configs))  # Should be sorted
    
    def test_list_configs_empty_directory(self):
        """Test listing configs in empty directory"""
        empty_manager = ConfigManager(tempfile.mkdtemp())
        configs = empty_manager.list_configs()
        
        self.assertEqual(configs, [])
    
    @patch('subprocess.run')
    def test_activate_config_success(self, mock_subprocess):
        """Test successful configuration activation"""
        mock_subprocess.return_value = Mock(returncode=0)
        
        result = self.manager.activate_config("server1")
        
        self.assertTrue(result)
        self.assertEqual(self.manager.active_config, "server1")
        self.assertEqual(mock_subprocess.call_count, 2)  # down + up commands
    
    @patch('subprocess.run')
    def test_activate_config_failure(self, mock_subprocess):
        """Test configuration activation failure"""
        mock_subprocess.return_value = Mock(returncode=1, stderr="Error message")
        
        result = self.manager.activate_config("server1")
        
        self.assertFalse(result)
        self.assertIsNone(self.manager.active_config)
    
    def test_activate_config_not_found(self):
        """Test activating non-existent configuration"""
        result = self.manager.activate_config("nonexistent")
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_activate_config_subprocess_error(self, mock_subprocess):
        """Test activation with subprocess exception"""
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'wg-quick')
        
        result = self.manager.activate_config("server1")
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_deactivate_config_success(self, mock_subprocess):
        """Test successful configuration deactivation"""
        mock_subprocess.return_value = Mock(returncode=0)
        self.manager.active_config = "server1"
        
        result = self.manager.deactivate_config()
        
        self.assertTrue(result)
        self.assertIsNone(self.manager.active_config)
    
    @patch('subprocess.run')
    def test_deactivate_config_failure(self, mock_subprocess):
        """Test configuration deactivation failure"""
        mock_subprocess.return_value = Mock(returncode=1, stderr="Deactivation error")
        
        result = self.manager.deactivate_config()
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_get_status_active(self, mock_subprocess):
        """Test getting status when VPN is active"""
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="interface: wg0\n  public key: abc123\n"
        )
        
        status = self.manager.get_status()
        
        self.assertTrue(status['active'])
        self.assertIn("interface: wg0", status['details'])
    
    @patch('subprocess.run')
    def test_get_status_inactive(self, mock_subprocess):
        """Test getting status when VPN is inactive"""
        mock_subprocess.return_value = Mock(returncode=0, stdout="")
        
        status = self.manager.get_status()
        
        self.assertFalse(status['active'])
        self.assertEqual(status['details'], "No active connections")
    
    @patch('subprocess.run')
    def test_get_status_error(self, mock_subprocess):
        """Test getting status with subprocess error"""
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'wg')
        
        status = self.manager.get_status()
        
        self.assertFalse(status['active'])
        self.assertEqual(status['details'], "Error checking status")


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple components"""
    
    @patch('subprocess.check_output')
    @patch('requests.get')
    def test_full_config_generation_workflow(self, mock_requests, mock_subprocess):
        """Test complete workflow from server fetch to config generation"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = [{
            'hostname': 'integration-test.nordvpn.com',
            'station': '10.0.0.1',
            'load': 15,
            'locations': [{'country': {'name': 'Test Country', 'code': 'TC'}}],
            'technologies': [{'identifier': 'wireguard_udp'}]
        }]