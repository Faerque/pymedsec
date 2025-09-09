"""
Example Hyperledger Fabric chaincode for PyMedSec audit logging.
This is a simple Go chaincode that provides the functions needed
by the HyperledgerBlockchainAdapter.

To use this chaincode:
1. Save as audit_chaincode.go
2. Deploy to your Hyperledger Fabric network
3. Configure PyMedSec to use your network and this chaincode
"""

package main

import (
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AuditContract provides functions for managing audit digests
type AuditContract struct {
    contractapi.Contract
}

// AuditRecord represents an audit record on the blockchain
type AuditRecord struct {
    Digest    string                 `json:"digest"`
    Timestamp string                 `json:"timestamp"`
    TxID      string                 `json:"txId"`
    Metadata  map[string]interface{} `json:"metadata"`
}

// SubmitDigest stores an audit digest on the blockchain
func (s *AuditContract) SubmitDigest(ctx contractapi.TransactionContextInterface, digest string, metadata string) error {
    // Parse metadata if provided
    var metadataMap map[string]interface{}
    if metadata != "" {
        if err := json.Unmarshal([]byte(metadata), &metadataMap); err != nil {
            metadataMap = make(map[string]interface{})
        }
    } else {
        metadataMap = make(map[string]interface{})
    }
    
    // Create audit record
    record := AuditRecord{
        Digest:    digest,
        Timestamp: time.Now().UTC().Format(time.RFC3339),
        TxID:      ctx.GetStub().GetTxID(),
        Metadata:  metadataMap,
    }
    
    // Store on blockchain
    recordJSON, err := json.Marshal(record)
    if err != nil {
        return err
    }
    
    return ctx.GetStub().PutState(digest, recordJSON)
}

// VerifyDigest verifies if a digest exists on the blockchain
func (s *AuditContract) VerifyDigest(ctx contractapi.TransactionContextInterface, digest string, txID string) (*map[string]interface{}, error) {
    recordJSON, err := ctx.GetStub().GetState(digest)
    if err != nil {
        return nil, fmt.Errorf("failed to read from world state: %v", err)
    }
    
    result := make(map[string]interface{})
    
    if recordJSON == nil {
        result["verified"] = false
        result["message"] = "Digest not found"
        return &result, nil
    }
    
    var record AuditRecord
    if err := json.Unmarshal(recordJSON, &record); err != nil {
        result["verified"] = false
        result["message"] = "Failed to parse record"
        return &result, nil
    }
    
    // Check if transaction ID matches (if provided)
    verified := true
    if txID != "" && record.TxID != txID {
        verified = false
    }
    
    result["verified"] = verified
    result["digest"] = record.Digest
    result["timestamp"] = record.Timestamp
    result["txId"] = record.TxID
    result["metadata"] = record.Metadata
    
    if verified {
        result["message"] = "Digest verified successfully"
    } else {
        result["message"] = "Transaction ID mismatch"
    }
    
    return &result, nil
}

// GetTransaction gets transaction details by digest
func (s *AuditContract) GetTransaction(ctx contractapi.TransactionContextInterface, digest string) (*AuditRecord, error) {
    recordJSON, err := ctx.GetStub().GetState(digest)
    if err != nil {
        return nil, fmt.Errorf("failed to read from world state: %v", err)
    }
    
    if recordJSON == nil {
        return nil, fmt.Errorf("digest %s does not exist", digest)
    }
    
    var record AuditRecord
    if err := json.Unmarshal(recordJSON, &record); err != nil {
        return nil, err
    }
    
    return &record, nil
}

func main() {
    chaincode, err := contractapi.NewChaincode(&AuditContract{})
    if err != nil {
        fmt.Printf("Error creating audit chaincode: %v", err)
        return
    }
    
    if err := chaincode.Start(); err != nil {
        fmt.Printf("Error starting audit chaincode: %v", err)
    }
}
