output "instance_id" {
  description = "Traffic-generator EC2 instance ID for SSH or Systems Manager targeting."
  value       = aws_instance.worker.id
}

output "public_ip" {
  description = "Elastic IPv4 address assigned to the traffic-generator worker."
  value       = aws_eip.worker.public_ip
}

output "ssh_command" {
  description = "Executable SSH command using the configured public-key path; revalidate operator_ssh_cidr before use."
  value       = var.ssh_public_key_path == null ? "ssh ubuntu@${aws_eip.worker.public_ip}" : "ssh -i ${pathexpand(trimsuffix(var.ssh_public_key_path, ".pub"))} ubuntu@${aws_eip.worker.public_ip}"
}

output "ssm_document_name" {
  description = "Validated Run Command document for canonical CSD scenarios and recovery access."
  value       = aws_ssm_document.run_scenario.name
}

output "evidence_bucket_name" {
  description = "Private encrypted bucket containing sanitized run evidence under runs/."
  value       = aws_s3_bucket.evidence.id
}

output "runtime_log_group_name" {
  description = "Encrypted CloudWatch log group for sanitized bootstrap and worker status."
  value       = aws_cloudwatch_log_group.runtime.name
}

output "public_subnet_id" {
  description = "Public worker subnet ID; automatic public addressing remains disabled."
  value       = aws_subnet.public.id
}

output "worker_security_group_id" {
  description = "Worker security group allowing SSH only from operator_ssh_cidr."
  value       = aws_security_group.worker.id
}

output "target_url" {
  description = "Exact authorized browser target."
  value       = var.target_url
}

output "source_commit" {
  description = "Immutable repository revision configured on the worker."
  value       = var.source_commit
}

output "deployment_manifest_sha256" {
  description = "Reviewed deployment-manifest digest recorded in runtime provenance."
  value       = var.deployment_manifest_sha256
}

output "termination_protection_enabled" {
  description = "Reminder that destroy requires separately approved termination-protection disablement."
  value       = aws_instance.worker.disable_api_termination
}


output "evidence_replica_bucket_name" {
  description = "Cross-region evidence replica bucket; retained objects block destroy until explicitly emptied."
  value       = aws_s3_bucket.evidence_replica.id
}

output "evidence_access_log_bucket_name" {
  description = "Dedicated same-region S3 server access-log sink; retained objects block destroy until explicitly emptied."
  value       = aws_s3_bucket.access_logs.id
}

output "evidence_replica_access_log_bucket_name" {
  description = "Dedicated replica-region S3 server access-log sink; retained objects block destroy until explicitly emptied."
  value       = aws_s3_bucket.replica_access_logs.id
}

output "vpc_flow_log_group_name" {
  description = "Encrypted CloudWatch log group receiving all VPC flow records."
  value       = aws_cloudwatch_log_group.vpc_flow.name
}
