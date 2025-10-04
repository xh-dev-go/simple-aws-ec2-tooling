package operation

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ListSecurityGroupRules lists the ingress rules for a specific security group.
func ListSecurityGroupRules(client *ec2.Client, securityGroupID, region string) {
	// Define the input parameters for the API call
	// We use a Filter to target a specific Security Group ID
	input := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{securityGroupID},
			},
		},
	}

	// Call the API
	result, err := client.DescribeSecurityGroupRules(context.TODO(), input)
	if err != nil {
		log.Fatalf("failed to describe security group rules: %v", err)
	}

	// Output the results
	fmt.Printf("Security Group Rules for ID: %s in region %s\n", securityGroupID, region)
	fmt.Println("---------------------------------------")

	for _, rule := range result.SecurityGroupRules {
		// Filter for Inbound (Ingress) rules for cleaner output
		if aws.ToBool(rule.IsEgress) {
			continue // Skip Outbound (Egress) rules
		}

		var source string
		if rule.CidrIpv4 != nil {
			source = *rule.CidrIpv4
		} else if rule.ReferencedGroupInfo != nil && rule.ReferencedGroupInfo.GroupId != nil {
			source = *rule.ReferencedGroupInfo.GroupId
		} else if rule.CidrIpv6 != nil {
			source = *rule.CidrIpv6
		}

		fmt.Printf("Rule ID: %s\n", aws.ToString(rule.SecurityGroupRuleId))
		fmt.Printf("  Protocol: %s\n", aws.ToString(rule.IpProtocol))

		// Handle port range display
		portRange := "All"
		if rule.FromPort != nil && rule.ToPort != nil {
			if *rule.FromPort == *rule.ToPort {
				portRange = fmt.Sprintf("%d", *rule.FromPort)
			} else {
				portRange = fmt.Sprintf("%d-%d", *rule.FromPort, *rule.ToPort)
			}
		}

		fmt.Printf("  Port(s):  %s\n", portRange)
		fmt.Printf("  Source:   %s\n", source)
		fmt.Printf("  Desc:     %s\n", aws.ToString(rule.Description))
		fmt.Println("---")
	}
}

// AddSecurityGroupRule adds an ingress rule to a security group.
func AddSecurityGroupRule(client *ec2.Client, securityGroupID, region, protocol, cidr, description string, fromPort, toPort int32) {
	input := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(securityGroupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String(protocol),
				FromPort:   aws.Int32(fromPort),
				ToPort:     aws.Int32(toPort),
				IpRanges: []types.IpRange{
					{
						CidrIp:      aws.String(cidr),
						Description: aws.String(description),
					},
				},
			},
		},
	}

	_, err := client.AuthorizeSecurityGroupIngress(context.TODO(), input)
	if err != nil {
		log.Fatalf("failed to authorize security group ingress: %v", err)
	}

	fmt.Printf("Successfully added rule to security group %s in region %s\n", securityGroupID, region)
}

// RevokeSecurityGroupRulesByDescription revokes ingress rules from a security group that match a description.
func RevokeSecurityGroupRulesByDescription(client *ec2.Client, securityGroupID, region, description string) {
	describeInput := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{securityGroupID},
			},
		},
	}

	result, err := client.DescribeSecurityGroupRules(context.TODO(), describeInput)
	if err != nil {
		log.Fatalf("failed to describe security group rules: %v", err)
	}

	var ruleIdsToRevoke []string
	for _, rule := range result.SecurityGroupRules {
		if !aws.ToBool(rule.IsEgress) && aws.ToString(rule.Description) == description {
			ruleIdsToRevoke = append(ruleIdsToRevoke, *rule.SecurityGroupRuleId)
		}
	}

	if len(ruleIdsToRevoke) == 0 {
		fmt.Printf("No ingress rules found with description '%s' in security group %s in region %s\n", description, securityGroupID, region)
		return
	}

	revokeInput := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:              aws.String(securityGroupID),
		SecurityGroupRuleIds: ruleIdsToRevoke,
	}

	_, err = client.RevokeSecurityGroupIngress(context.TODO(), revokeInput)
	if err != nil {
		log.Fatalf("failed to revoke security group ingress rules: %v", err)
	}

	fmt.Printf("Successfully revoked %d rule(s) with description '%s' from security group %s in region %s\n", len(ruleIdsToRevoke), description, securityGroupID, region)
}

// RevokeSecurityGroupRulesByDescriptionPrefix revokes ingress rules where the description starts with a given prefix.
func RevokeSecurityGroupRulesByDescriptionPrefix(client *ec2.Client, securityGroupID, region, prefix string) {
	describeInput := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{securityGroupID},
			},
		},
	}

	result, err := client.DescribeSecurityGroupRules(context.TODO(), describeInput)
	if err != nil {
		log.Fatalf("failed to describe security group rules: %v", err)
	}

	var ruleIdsToRevoke []string
	for _, rule := range result.SecurityGroupRules {
		if !aws.ToBool(rule.IsEgress) && strings.HasPrefix(aws.ToString(rule.Description), prefix) {
			ruleIdsToRevoke = append(ruleIdsToRevoke, *rule.SecurityGroupRuleId)
		}
	}

	if len(ruleIdsToRevoke) == 0 {
		fmt.Printf("No ingress rules found with description starting with '%s' in security group %s in region %s\n", prefix, securityGroupID, region)
		return
	}

	revokeInput := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:              aws.String(securityGroupID),
		SecurityGroupRuleIds: ruleIdsToRevoke,
	}

	_, err = client.RevokeSecurityGroupIngress(context.TODO(), revokeInput)
	if err != nil {
		log.Fatalf("failed to revoke security group ingress rules: %v", err)
	}

	fmt.Printf("Successfully revoked %d rule(s) with description starting with '%s' from security group %s in region %s\n", len(ruleIdsToRevoke), prefix, securityGroupID, region)
}

// RevokeSecurityGroupRulesByPort revokes ingress rules that match a port.
func RevokeSecurityGroupRulesByPort(client *ec2.Client, securityGroupID, region string, port int32) {
	describeInput := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{{Name: aws.String("group-id"), Values: []string{securityGroupID}}},
	}
	result, err := client.DescribeSecurityGroupRules(context.TODO(), describeInput)
	if err != nil {
		log.Fatalf("failed to describe security group rules: %v", err)
	}

	var ruleIdsToRevoke []string
	for _, rule := range result.SecurityGroupRules {
		if !aws.ToBool(rule.IsEgress) && rule.FromPort != nil && *rule.FromPort == port && rule.ToPort != nil && *rule.ToPort == port {
			ruleIdsToRevoke = append(ruleIdsToRevoke, *rule.SecurityGroupRuleId)
		}
	}

	if len(ruleIdsToRevoke) == 0 {
		fmt.Printf("No ingress rules found for port %d in security group %s in region %s\n", port, securityGroupID, region)
		return
	}

	revokeInput := &ec2.RevokeSecurityGroupIngressInput{GroupId: aws.String(securityGroupID), SecurityGroupRuleIds: ruleIdsToRevoke}
	_, err = client.RevokeSecurityGroupIngress(context.TODO(), revokeInput)
	if err != nil {
		log.Fatalf("failed to revoke security group ingress rules: %v", err)
	}
	fmt.Printf("Successfully revoked %d rule(s) for port %d from security group %s in region %s\n", len(ruleIdsToRevoke), port, securityGroupID, region)
}

// RevokeSecurityGroupRulesByIpPort revokes ingress rules that match a CIDR and port.
func RevokeSecurityGroupRulesByIpPort(client *ec2.Client, securityGroupID, region, cidr string, port int32) {
	describeInput := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{{Name: aws.String("group-id"), Values: []string{securityGroupID}}},
	}
	result, err := client.DescribeSecurityGroupRules(context.TODO(), describeInput)
	if err != nil {
		log.Fatalf("failed to describe security group rules: %v", err)
	}

	var ruleIdsToRevoke []string
	for _, rule := range result.SecurityGroupRules {
		if !aws.ToBool(rule.IsEgress) && (aws.ToString(rule.CidrIpv4) == cidr || aws.ToString(rule.CidrIpv6) == cidr) && rule.FromPort != nil && *rule.FromPort == port && rule.ToPort != nil && *rule.ToPort == port {
			ruleIdsToRevoke = append(ruleIdsToRevoke, *rule.SecurityGroupRuleId)
		}
	}

	if len(ruleIdsToRevoke) == 0 {
		fmt.Printf("No ingress rules found for CIDR %s and port %d in security group %s in region %s\n", cidr, port, securityGroupID, region)
		return
	}

	revokeInput := &ec2.RevokeSecurityGroupIngressInput{GroupId: aws.String(securityGroupID), SecurityGroupRuleIds: ruleIdsToRevoke}
	_, err = client.RevokeSecurityGroupIngress(context.TODO(), revokeInput)
	if err != nil {
		log.Fatalf("failed to revoke security group ingress rules: %v", err)
	}
	fmt.Printf("Successfully revoked %d rule(s) for CIDR %s and port %d from security group %s in region %s\n", len(ruleIdsToRevoke), cidr, port, securityGroupID, region)
}

// PurgeSecurityGroupRules revokes all ingress rules from a security group.
func PurgeSecurityGroupRules(client *ec2.Client, securityGroupID, region string) {
	// First, list all rules to show what will be deleted.
	fmt.Printf("The following ingress rules will be purged from security group %s in region %s:\n", securityGroupID, region)
	ListSecurityGroupRules(client, securityGroupID, region)

	describeInput := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{securityGroupID},
			},
		},
	}

	result, err := client.DescribeSecurityGroupRules(context.TODO(), describeInput)
	if err != nil {
		log.Fatalf("failed to describe security group rules before purging: %v", err)
	}

	var ruleIdsToRevoke []string
	for _, rule := range result.SecurityGroupRules {
		if !aws.ToBool(rule.IsEgress) {
			ruleIdsToRevoke = append(ruleIdsToRevoke, *rule.SecurityGroupRuleId)
		}
	}

	if len(ruleIdsToRevoke) == 0 {
		fmt.Printf("\nNo ingress rules found to purge in security group %s in region %s.\n", securityGroupID, region)
		return
	}

	revokeInput := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:              aws.String(securityGroupID),
		SecurityGroupRuleIds: ruleIdsToRevoke,
	}

	_, err = client.RevokeSecurityGroupIngress(context.TODO(), revokeInput)
	if err != nil {
		log.Fatalf("failed to purge security group ingress rules: %v", err)
	}

	fmt.Printf("\nSuccessfully purged %d ingress rule(s) from security group %s in region %s.\n", len(ruleIdsToRevoke), securityGroupID, region)
}
