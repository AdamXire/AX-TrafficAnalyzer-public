"""
AX-TrafficAnalyzer - Phase 8 File Validation Tests
Copyright © 2025 MMeTech (Macau) Ltd.
"""

import pytest
from pathlib import Path


class TestPhase8Docker:
    """Test Docker deployment files."""
    
    def test_dockerfile_exists(self):
        assert Path("docker/Dockerfile").exists()
    
    def test_dockerignore_exists(self):
        assert Path("docker/.dockerignore").exists()
    
    def test_docker_compose_exists(self):
        assert Path("docker/docker-compose.yml").exists()
    
    def test_docker_compose_prod_exists(self):
        assert Path("docker/docker-compose.prod.yml").exists()
    
    def test_entrypoint_exists(self):
        assert Path("docker/entrypoint.sh").exists()
    
    def test_prometheus_config_exists(self):
        assert Path("docker/prometheus.yml").exists()


class TestPhase8LoadTests:
    """Test load testing files."""
    
    def test_locustfile_exists(self):
        assert Path("tests/load/locustfile.py").exists()
    
    def test_load_test_script_exists(self):
        assert Path("scripts/run-load-test.sh").exists()


class TestPhase8Security:
    """Test security scanning files."""
    
    def test_security_scan_script_exists(self):
        assert Path("scripts/security-scan.sh").exists()
    
    def test_security_workflow_exists(self):
        assert Path(".github/workflows/security.yml").exists()
    
    def test_security_md_exists(self):
        assert Path("SECURITY.md").exists()


class TestPhase8Kubernetes:
    """Test Kubernetes manifest files."""
    
    def test_k8s_namespace_exists(self):
        assert Path("k8s/namespace.yaml").exists()
    
    def test_k8s_deployment_exists(self):
        assert Path("k8s/deployment.yaml").exists()
    
    def test_k8s_service_exists(self):
        assert Path("k8s/service.yaml").exists()
    
    def test_k8s_configmap_exists(self):
        assert Path("k8s/configmap.yaml").exists()
    
    def test_k8s_pvc_exists(self):
        assert Path("k8s/pvc.yaml").exists()
    
    def test_k8s_rbac_exists(self):
        assert Path("k8s/rbac.yaml").exists()
    
    def test_k8s_kustomization_exists(self):
        assert Path("k8s/kustomization.yaml").exists()


class TestPhase8Documentation:
    """Test documentation files."""
    
    def test_installation_guide_exists(self):
        assert Path("docs/installation.md").exists()
    
    def test_troubleshooting_guide_exists(self):
        assert Path("docs/troubleshooting.md").exists()


class TestPhase8Ansible:
    """Test Ansible automation files."""
    
    def test_ansible_playbook_exists(self):
        assert Path("ansible/playbook.yml").exists()
    
    def test_ansible_inventory_exists(self):
        assert Path("ansible/inventory/production").exists()
    
    def test_ansible_group_vars_exists(self):
        assert Path("ansible/group_vars/all.yml").exists()
    
    def test_ansible_common_role_exists(self):
        assert Path("ansible/roles/common/tasks/main.yml").exists()
    
    def test_ansible_ax_traffic_role_exists(self):
        assert Path("ansible/roles/ax-traffic/tasks/main.yml").exists()
    
    def test_ansible_monitoring_role_exists(self):
        assert Path("ansible/roles/monitoring/tasks/main.yml").exists()

