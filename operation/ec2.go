package operation

import (
	"context"

	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// InstanceInfo holds details about an EC2 instance.
type InstanceInfo struct {
	ID    string
	Name  string
	Type  string
	State string
}

// ListEC2Instances retrieves a list of EC2 instances in the specified region.
func ListEC2Instances(client *ec2.Client) ([]InstanceInfo, error) {
	output, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	var instances []InstanceInfo
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			nameTag := "N/A"
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					nameTag = *tag.Value
					break
				}
			}
			instances = append(instances, InstanceInfo{
				ID: *instance.InstanceId, Name: nameTag, Type: string(instance.InstanceType), State: string(instance.State.Name)})
		}
	}
	return instances, nil
}

// FindEC2InstancesByName finds EC2 instances that have a specific "Name" tag.
func FindEC2InstancesByName(client *ec2.Client, name string) ([]InstanceInfo, error) {
	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{name},
			},
		},
	}

	output, err := client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	var instances []InstanceInfo
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			nameTag := "N/A"
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					nameTag = *tag.Value
					break
				}
			}
			instances = append(instances, InstanceInfo{
				ID:    *instance.InstanceId,
				Name:  nameTag,
				Type:  string(instance.InstanceType),
				State: string(instance.State.Name),
			})
		}
	}

	return instances, nil
}

// GetEC2InstancePublicIP retrieves the public IP address for a given instance ID.
func GetEC2InstancePublicIP(client *ec2.Client, instanceID string) (string, error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	output, err := client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return "", err
	}

	if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("instance with ID '%s' not found", instanceID)
	}

	instance := output.Reservations[0].Instances[0]
	if instance.PublicIpAddress == nil {
		return "", fmt.Errorf("instance with ID '%s' does not have a public IP address", instanceID)
	}

	return *instance.PublicIpAddress, nil
}
