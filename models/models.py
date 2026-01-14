from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime



# Pydantic models for Shodan API responses
class Location(BaseModel):
    city: Optional[str] = None
    region_code: Optional[str] = None
    area_code: Optional[str] = None
    longitude: Optional[float] = None
    country_name: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None


class DNS(BaseModel):
    resolver_hostname: Optional[str] = None
    recursive: Optional[bool] = None
    resolver_id: Optional[str] = None
    software: Optional[str] = None


class ShodanMetadata(BaseModel):
    region: Optional[str] = None
    module: Optional[str] = None
    ptr: Optional[bool] = None
    options: Optional[Dict[str, Any]] = None
    id: Optional[str] = None
    crawler: Optional[str] = None


class Redirect(BaseModel):
    host: Optional[str] = None
    data: Optional[str] = None
    location: Optional[str] = None


class Favicon(BaseModel):
    hash: Optional[int] = None
    data: Optional[str] = None
    location: Optional[str] = None


class Component(BaseModel):
    categories: Optional[List[str]] = None


class HTTP(BaseModel):
    status: Optional[int] = None
    robots_hash: Optional[int] = None
    redirects: Optional[List[Redirect]] = None
    title_hash: Optional[int] = None
    favicon: Optional[Favicon] = None
    securitytxt: Optional[str] = None
    title: Optional[str] = None
    sitemap_hash: Optional[int] = None
    html_hash: Optional[int] = None
    robots: Optional[str] = None
    server: Optional[str] = None
    headers_hash: Optional[int] = None
    host: Optional[str] = None
    html: Optional[str] = None
    location: Optional[str] = None
    components: Optional[Dict[str, Component]] = None
    securitytxt_hash: Optional[int] = None
    dom_hash: Optional[int] = None
    sitemap: Optional[str] = None
    server_hash: Optional[int] = None


class SSL(BaseModel):
    chain_sha256: Optional[List[str]] = None
    jarm: Optional[str] = None
    tlsext: Optional[List[Dict[str, Any]]] = None
    chain: Optional[List[str]] = None
    cipher: Optional[Dict[str, Any]] = None
    trust: Optional[Dict[str, Any]] = None
    versions: Optional[List[str]] = None
    acceptable_cas: Optional[List[str]] = None
    cert: Optional[Dict[str, Any]] = None
    alpn: Optional[List[str]] = None
    ja3s: Optional[str] = None


class ServiceData(BaseModel):
    hash: Optional[int] = None
    opts: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    isp: Optional[str] = None
    data: Optional[str] = None
    shodan: Optional[ShodanMetadata] = Field(None, alias='_shodan')
    port: Optional[int] = None
    hostnames: Optional[List[str]] = None
    location: Optional[Location] = None
    dns: Optional[DNS] = None
    ip: Optional[int] = None
    domains: Optional[List[str]] = None
    org: Optional[str] = None
    os: Optional[str] = None
    asn: Optional[str] = None
    transport: Optional[str] = None
    ip_str: Optional[str] = None
    http: Optional[HTTP] = None
    ssl: Optional[SSL] = None

    class Config:
        populate_by_name = True


class ShodanHost(BaseModel):
    city: Optional[str] = None
    region_code: Optional[str] = None
    os: Optional[str] = None
    tags: Optional[List[str]] = None
    ip: Optional[int] = None
    isp: Optional[str] = None
    area_code: Optional[str] = None
    longitude: Optional[float] = None
    last_update: Optional[datetime] = None
    ports: Optional[List[int]] = None
    latitude: Optional[float] = None
    hostnames: Optional[List[str]] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    domains: Optional[List[str]] = None
    org: Optional[str] = None
    data: Optional[List[ServiceData]] = None
    asn: Optional[str] = None
    ip_str: Optional[str] = None


# Pydantic models for AbuseDB API Responses 

class AbuseDBHost(BaseModel):
        ipAddress: Optional[str] = None
        isPublic: Optional[bool] = None
        ipVersion: Optional[int] = None
        isWhitelisted: Optional[bool] = None
        abuseConfidenceScore: Optional[int] = None
        countryCode: Optional[str] = None
        usageType: Optional[str] = None
        isp: Optional[str] = None
        domain: Optional[str] = None
        totalReports: Optional[int] = None
        lastReportedAt: Optional[datetime] = None


