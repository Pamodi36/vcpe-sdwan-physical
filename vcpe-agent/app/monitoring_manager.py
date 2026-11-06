#!/usr/bin/env python3                                                                
# coding: utf-8                                                                        
import os
import json
import logging
import requests                                                                     

class MonitoringManager:                                                               
    def __init__(self):      
        self.monitoring_base_url = "http://host.docker.internal:9100/api/v1"                                                       
        
    def _as_list(self, value):                                                            # helper to normalize a value into a list
        if value is None:                                                              
            return []                                                                  
        if isinstance(value, list):                                                    
            return value                                                                  # if the value is already a list return it as it is
        return [value]                                                                    # otherwise wrap a single value as a list

    def _ip_from_prefix(self, prefix):                                                     # helper to extract IP from prefix
        if not prefix:                                                                     # if prefix is missing, no destination IP can be extracted
            return None                                                                  
        return str(prefix).split("/", 1)[0]                                                # convert 192.168.10.2/24 into 192.168.10.2

    def start_underlay_flow_monitoring(self, traffic_class, steering_policy, flow_id, wan_link_name):
    
        five_tuple = traffic_class.get("five-tuple", {})
    
        dst_prefix = five_tuple.get("dst-prefix")
        destination_ip = self._ip_from_prefix(dst_prefix)
        if not destination_ip:
            raise ValueError("Cannot start underlay monitoring without destination")
    
        # ---------------------------------------------------------
        # Five tuple used by passive monitoring to isolate a Traffic class
        # ---------------------------------------------------------
        flow_filter = {
            "src_prefix": five_tuple.get("src-prefix"),
            "dst_prefix": five_tuple.get("dst-prefix"),
            "l4_protocol": five_tuple.get("l4-protocol"),
            "src_port": five_tuple.get("src-port"),
            "dst_port": five_tuple.get("dst-port")
        }
    
        flow_filter = {
            key: value
            for key, value in flow_filter.items()
            if value is not None }
    
        # ---------------------------------------------------------
        # SLO required by monitoring adaptive rule engine
        # ---------------------------------------------------------
        slo = {
            "max_latency_ms": steering_policy.get("max-latency-ms"),
            "max_jitter_ms": steering_policy.get("max-jitter-ms"),
            "max_loss_percent": steering_policy.get("max-loss-percent"),
            "min_bandwidth_kbps": steering_policy.get("min-bandwidth-kbps") }
    
        slo = {
            key: value
            for key, value in slo.items()
            if value is not None }
    
        payload = {
            "flow_id": str(flow_id),
            "wan_link": str(wan_link_name),
            "destination_ip": destination_ip,
            "flow_filter": flow_filter,
            "slo": slo,
        }
    
        url = f"{self.monitoring_base_url}/monitoring/flows"
    
        logging.info("Creating/updating underlay monitoring job: %s", payload)
    
        response = requests.post(url, json=payload, timeout=5)
    
        response.raise_for_status()
    
        return payload

    def stop_underlay_flow_monitoring(self, flow_id, wan_link_name):        
        url = f"{self.monitoring_base_url}/monitoring/flows/{flow_id}/{wan_link_name}"        # vcpe-monitoring endpoint for deleting flow monitor 
                    
        logging.info("Stopping flow monitoring for flow_id=%s wan_link=%s", flow_id, wan_link_name)
                
        response = requests.delete(url, timeout=5)                                        # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                   

    def start_overlay_tunnel_monitoring(self, tunnel, steering_policy):                                   
        tunnel_id = tunnel.get("name")           
        if not tunnel_id:
            raise ValueError("Cannot start tunnel monitoring without tunnel name")
        
        resolved_peer = tunnel.get("resolved-peer", {})                                
        destination_ip = resolved_peer.get("peer-local-address")                                # use peer local WG tunnel address as tunnel monitoring destination

        if not tunnel_id:                                                              
            raise ValueError("Cannot start tunnel monitoring without tunnel name")       

        if not destination_ip:                                                           
            raise ValueError("Cannot start tunnel monitoring without peer-address")  

        slo = {
            "max_latency_ms": steering_policy.get("max-latency-ms"),
            "max_jitter_ms": steering_policy.get("max-jitter-ms"),
            "max_loss_percent": steering_policy.get("max-loss-percent"),
            "min_bandwidth_kbps": steering_policy.get("min-bandwidth-kbps")
        }
        
        slo = {
            key: value
            for key, value in slo.items()
            if value is not None
        }

        payload = {                                                                      # payload sent to vcpe-monitoring
            "tunnel_id": str(tunnel_id),                                                 # overlay tunnel ID; not a flow_id
            "destination_ip": destination_ip,            
            "slo": slo,
        }

        url = f"{self.monitoring_base_url}/monitoring/tunnels"                           # vcpe-monitoring endpoint for tunnel monitoring  
            
        logging.info("Sending tunnel monitoring request: %s", payload)                   

        response = requests.post(url, json=payload, timeout=5)                           # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      

        return payload                                                                  

    def stop_overlay_tunnel_monitoring(self, tunnel_id):                                  
        url = f"{self.monitoring_base_url}/monitoring/tunnels/{tunnel_id}"               # vcpe-monitoring endpoint for deleting tunnel monitor  
                    
        logging.info("Stopping tunnel monitoring for tunnel_id=%s", tunnel_id)           

        response = requests.delete(url, timeout=5)                                       # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                     
