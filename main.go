package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/xh-dev-go/security-group-updates/operation"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

var (
	client    *ec2.Client
	awsRegion string
)

var rootCmd = &cobra.Command{
	Use:   "sg-manager",
	Short: "A CLI tool to manage AWS Security Group rules.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// The 'awsRegion' variable is now bound to the --region flag by Cobra.
		// If the flag is not set, we check the environment variable, then use a default.
		if awsRegion == "" {
			awsRegion = os.Getenv("AWS_REGION")
		}
		if awsRegion == "" {
			awsRegion = "ap-northeast-1" // Default region
		}

		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
		if err != nil {
			log.Fatalf("failed to load configuration: %v", err)
		}
		client = ec2.NewFromConfig(cfg)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists ingress rules for a security group.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		operation.ListSecurityGroupRules(client, sgID, awsRegion)
	},
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Adds an ingress rule to a security group.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		protocol, _ := cmd.Flags().GetString("protocol")
		port, _ := cmd.Flags().GetInt32("port")
		cidr, _ := cmd.Flags().GetString("cidr")
		description, _ := cmd.Flags().GetString("description")

		operation.AddSecurityGroupRule(client, sgID, awsRegion, protocol, cidr, description, port, port)
	},
}

var revokeRootCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke security group rules by different criteria.",
}

var revokeByDescCmd = &cobra.Command{
	Use:   "match-by-desc",
	Short: "Revokes ingress rules by exact description match.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		description, _ := cmd.Flags().GetString("description")
		operation.RevokeSecurityGroupRulesByDescription(client, sgID, awsRegion, description)
	},
}

var revokeByDescPrefixCmd = &cobra.Command{
	Use:   "desc-starts-with",
	Short: "Revokes ingress rules where the description starts with a prefix.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		prefix, _ := cmd.Flags().GetString("prefix")
		operation.RevokeSecurityGroupRulesByDescriptionPrefix(client, sgID, awsRegion, prefix)
	},
}

var revokeByPortCmd = &cobra.Command{
	Use:   "match-by-port",
	Short: "Revokes ingress rules by port.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		port, _ := cmd.Flags().GetInt32("port")
		operation.RevokeSecurityGroupRulesByPort(client, sgID, awsRegion, port)
	},
}

var revokeByIpPortCmd = &cobra.Command{
	Use:   "match-by-ip-port",
	Short: "Revokes ingress rules by IP/CIDR and port.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		port, _ := cmd.Flags().GetInt32("port")
		cidr, _ := cmd.Flags().GetString("cidr")
		operation.RevokeSecurityGroupRulesByIpPort(client, sgID, awsRegion, cidr, port)
	},
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Lists and then removes all ingress rules from a security group.",
	Run: func(cmd *cobra.Command, args []string) {
		sgID, _ := cmd.Flags().GetString("security-group-id")
		operation.PurgeSecurityGroupRules(client, sgID, awsRegion)
	},
}

func init() {
	// Add a persistent flag for the region to the root command
	rootCmd.PersistentFlags().StringVarP(&awsRegion, "region", "r", "", "The AWS region to use (overrides AWS_REGION environment variable)")

	// list command flags
	listCmd.Flags().StringP("security-group-id", "s", "", "The ID of the security group")
	listCmd.MarkFlagRequired("security-group-id")

	// add command flags
	addCmd.Flags().StringP("security-group-id", "s", "", "The ID of the security group")
	addCmd.Flags().StringP("protocol", "p", "tcp", "The protocol (e.g., tcp, udp, icmp)")
	addCmd.Flags().Int32P("port", "", 0, "The port number")
	addCmd.Flags().StringP("cidr", "c", "", "The CIDR block (e.g., 192.168.1.1/32)")
	addCmd.Flags().StringP("description", "d", "", "The rule description")
	addCmd.MarkFlagRequired("security-group-id")
	addCmd.MarkFlagRequired("port")
	addCmd.MarkFlagRequired("cidr")
	addCmd.MarkFlagRequired("description")

	// purge command flags
	purgeCmd.Flags().StringP("security-group-id", "s", "", "The ID of the security group to purge")
	purgeCmd.MarkFlagRequired("security-group-id")

	// Revoke command structure
	revokeRootCmd.PersistentFlags().StringP("security-group-id", "s", "", "The ID of the security group")
	revokeRootCmd.MarkPersistentFlagRequired("security-group-id")

	// Flags for 'revoke match-by-desc'
	revokeByDescCmd.Flags().StringP("description", "d", "", "The exact description of the rule(s) to revoke")
	revokeByDescCmd.MarkFlagRequired("description")

	// Flags for 'revoke desc-starts-with'
	revokeByDescPrefixCmd.Flags().StringP("prefix", "p", "", "The description prefix of the rule(s) to revoke")
	revokeByDescPrefixCmd.MarkFlagRequired("prefix")

	// Flags for 'revoke match-by-port'
	revokeByPortCmd.Flags().Int32P("port", "", 0, "The port of the rule(s) to revoke")
	revokeByPortCmd.MarkFlagRequired("port")

	// Flags for 'revoke match-by-ip-port'
	revokeByIpPortCmd.Flags().Int32P("port", "", 0, "The port of the rule(s) to revoke")
	revokeByIpPortCmd.Flags().StringP("cidr", "c", "", "The CIDR of the rule(s) to revoke")
	revokeByIpPortCmd.MarkFlagRequired("port")
	revokeByIpPortCmd.MarkFlagRequired("cidr")

	revokeRootCmd.AddCommand(revokeByDescCmd, revokeByDescPrefixCmd, revokeByPortCmd, revokeByIpPortCmd)
	rootCmd.AddCommand(listCmd, addCmd, revokeRootCmd, purgeCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
