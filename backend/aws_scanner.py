#!/usr/bin/env python3
"""
aws_scanner.py
Simple CSPM scanner that collects basic AWS configuration
and writes aws_config.json for the Java compliance engine.
Supports a --dry-run mode for testing without AWS credentials.
"""

import boto3
import botocore
import json
import os
import argparse
import logging
from typing import Dict, Any

# ---- Config ----
OUTPUT_FILE = r"D:\EIS\CSPM PROJECT\aws_config_5.json"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("aws_scanner")


# ---- Utility: safe boto3 client creation ----
def make_client(service: str, region: str = None, aws_access_key_id=None, aws_secret_access_key=None):
    """Create a boto3 client safely with proper region and credentials."""
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    if aws_access_key_id and aws_secret_access_key:
        kwargs["aws_access_key_id"] = aws_access_key_id
        kwargs["aws_secret_access_key"] = aws_secret_access_key

    try:
        client = boto3.client(service, **kwargs)
        return client
    except Exception as e:
        logger.error("Failed to create boto3 client for %s: %s", service, e)
        raise


# ---- S3 checks ----
def scan_s3(s3_client) -> Dict[str, Any]:
    logger.info("Scanning S3 buckets...")
    out = {}
    try:
        resp = s3_client.list_buckets()
        buckets = resp.get("Buckets", [])
        out["BucketCount"] = len(buckets)
        out["Buckets"] = []

        for b in buckets:
            name = b["Name"]
            info = {"Name": name}

            # Public access block
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                info["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration", {})
            except botocore.exceptions.ClientError as e:
                info["PublicAccessBlock"] = {"error": str(e)}

            # ACL public check
            try:
                acl = s3_client.get_bucket_acl(Bucket=name)
                grants = acl.get("Grants", [])
                public = any(
                    g.get("Grantee", {}).get("URI", "").endswith("AllUsers") or
                    g.get("Grantee", {}).get("URI", "").endswith("AuthenticatedUsers")
                    for g in grants
                )
                info["ACL_Public"] = public
            except Exception:
                info["ACL_Public"] = False

            # Versioning
            try:
                ver = s3_client.get_bucket_versioning(Bucket=name)
                info["Versioning"] = ver.get("Status", "Disabled")
            except Exception:
                info["Versioning"] = "Unknown"

            # Encryption
            try:
                s3_client.get_bucket_encryption(Bucket=name)
                info["Encryption"] = True
            except botocore.exceptions.ClientError:
                info["Encryption"] = False

            out["Buckets"].append(info)

    except Exception as e:
        logger.exception("S3 scan failed: %s", e)
        out["error"] = str(e)

    return out


# ---- IAM checks ----
def scan_iam(iam_client) -> Dict[str, Any]:
    logger.info("Scanning IAM...")
    out = {}
    try:
        account_summary = iam_client.get_account_summary()
        out["AccountSummary"] = account_summary.get("SummaryMap", {})

        users = iam_client.list_users().get("Users", [])
        out["UserCount"] = len(users)
        user_mfa = {}

        for u in users:
            uname = u["UserName"]
            try:
                mfa = iam_client.list_mfa_devices(UserName=uname).get("MFADevices", [])
                user_mfa[uname] = len(mfa) > 0
            except Exception:
                user_mfa[uname] = "error"
        out["UserMFA"] = user_mfa

        roles = iam_client.list_roles().get("Roles", [])
        out["RoleCount"] = len(roles)

    except Exception as e:
        logger.exception("IAM scan failed: %s", e)
        out["error"] = str(e)
    return out


# ---- EC2 checks ----
def scan_ec2(ec2_client) -> Dict[str, Any]:
    logger.info("Scanning EC2 instances and security groups...")
    out = {}
    try:
        instances = []
        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instances.append({
                        "InstanceId": inst.get("InstanceId"),
                        "State": inst.get("State", {}).get("Name"),
                        "Tags": inst.get("Tags", []),
                        "SecurityGroups": inst.get("SecurityGroups", [])
                    })
        out["Instances"] = instances

        # Security groups
        sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
        sg_info = []
        for sg in sgs:
            ingress = []
            for p in sg.get("IpPermissions", []):
                ports = []
                if "FromPort" in p and "ToPort" in p:
                    ports = list(range(p["FromPort"], p["ToPort"] + 1))
                cidrs = [ipr.get("CidrIp") for ipr in p.get("IpRanges", [])]
                ingress.append({
                    "IpProtocol": p.get("IpProtocol"),
                    "Ports": ports,
                    "Cidrs": cidrs
                })
            sg_info.append({
                "GroupId": sg.get("GroupId"),
                "GroupName": sg.get("GroupName"),
                "Ingress": ingress
            })
        out["SecurityGroups"] = sg_info

    except Exception as e:
        logger.exception("EC2 scan failed: %s", e)
        out["error"] = str(e)
    return out


# ---- RDS checks ----
def scan_rds(rds_client) -> Dict[str, Any]:
    logger.info("Scanning RDS instances...")
    out = {}
    try:
        dbs = rds_client.describe_db_instances().get("DBInstances", [])
        db_info = []
        for db in dbs:
            db_info.append({
                "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                "StorageEncrypted": db.get("StorageEncrypted", False),
                "BackupRetentionPeriod": db.get("BackupRetentionPeriod", 0),
                "MultiAZ": db.get("MultiAZ", False),
            })
        out["RDSInstances"] = db_info
    except Exception as e:
        logger.exception("RDS scan failed: %s", e)
        out["error"] = str(e)
    return out


# ---- VPC checks ----
def scan_vpc(ec2_client) -> Dict[str, Any]:
    logger.info("Scanning VPCs and network ACLs...")
    out = {}
    try:
        vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
        out["VPCCount"] = len(vpcs)

        nacls = ec2_client.describe_network_acls().get("NetworkAcls", [])
        out["NetworkAcls"] = [{"NetworkAclId": n.get("NetworkAclId"), "Entries": n.get("Entries")} for n in nacls]
    except Exception as e:
        logger.exception("VPC scan failed: %s", e)
        out["error"] = str(e)
    return out


# ---- Main scan orchestration ----
def run_scan(region: str = "us-east-1", aws_key=None, aws_secret=None, dry_run=False) -> Dict[str, Any]:
    logger.info("Starting CSPM scan (region=%s, dry_run=%s)...", region, dry_run)
    report = {"Region": region, "dry_run": dry_run}

    if dry_run:
        logger.info("Dry-run mode: returning mock data.")
        report.update({
            "S3": {"BucketCount": 1, "Buckets": [{"Name": "example-bucket", "PublicAccessBlock": {}, "ACL_Public": False, "Versioning": "Enabled", "Encryption": True}]},
            "IAM": {"UserCount": 1, "UserMFA": {"admin": True}, "RoleCount": 1},
            "EC2": {"Instances": [{"InstanceId": "i-012345", "State": "running", "SecurityGroups": []}], "SecurityGroups": []},
            "RDS": {"RDSInstances": []},
            "VPC": {"VPCCount": 1}
        })
        return report

    try:
        s3 = make_client("s3", region, aws_key, aws_secret)
        iam = make_client("iam", region, aws_key, aws_secret)
        ec2 = make_client("ec2", region, aws_key, aws_secret)
        rds = make_client("rds", region, aws_key, aws_secret)
    except Exception as e:
        raise RuntimeError("Failed to initialize AWS clients: " + str(e))

    report["S3"] = scan_s3(s3)
    report["IAM"] = scan_iam(iam)
    report["EC2"] = scan_ec2(ec2)
    report["RDS"] = scan_rds(rds)
    report["VPC"] = scan_vpc(ec2)

    return report


# ---- Save JSON ----
def save_report(data: Dict[str, Any], path: str = OUTPUT_FILE):
    logger.info("Saving scan output to %s", path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info("Saved.")


# ---- CLI ----
def parse_args():
    p = argparse.ArgumentParser(description="Simple AWS scanner for CSPM project")
    p.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"), help="AWS region")
    p.add_argument("--aws-key", default=None, help="AWS Access Key ID")
    p.add_argument("--aws-secret", default=None, help="AWS Secret Access Key")
    p.add_argument("--dry-run", action="store_true", help="Run without AWS (mock data)")
    p.add_argument("--output", default=OUTPUT_FILE, help="Output JSON file name")
    return p.parse_args()


def main():
    args = parse_args()
    aws_key = args.aws_key or os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret = args.aws_secret or os.getenv("AWS_SECRET_ACCESS_KEY")

    try:
        data = run_scan(region=args.region, aws_key=aws_key, aws_secret=aws_secret, dry_run=args.dry_run)
        save_report(data, path=args.output)
        logger.info("Scan completed successfully. Output: %s", args.output)
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        exit(1)


if __name__ == "__main__":
    main()
