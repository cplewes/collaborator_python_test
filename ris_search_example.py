#!/usr/bin/env python3
"""
Simple example of using the RIS Search Client

This script demonstrates basic usage of the RIS search functionality
with predefined search examples.
"""

import getpass
from ris_search_client import RISSearchClient, QuerySearchScreenDTO, QuerySearchScreenFilterSetDTO

def main():
    print("=== RIS Search Example ===")
    
    # Get credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Create and authenticate client
    client = RISSearchClient()
    if not client.authenticate(username, password):
        print("❌ Authentication failed")
        return
    
    print("\n[+] Authentication successful!")
    
    # Example 1: Simple search with basic filters
    print("\n🔍 Example 1: Basic Search")
    result = client.search_simple(
        query_name="basic_search",
        filters={
            "status": "active",
            "type": "study"
        },
        optional_fields=["dicomName", "dicomCode"]
    )
    
    if result:
        print(f"✅ Found {result.total} results")
        for i, item in enumerate(result.results[:3], 1):  # Show first 3 results
            print(f"  [{i}] {item.name} (Code: {item.code})")
    else:
        print("❌ Search failed")
    
    # Example 2: Advanced search with custom filter sets
    print("\n🔍 Example 2: Advanced Search")
    
    # Create custom filter sets
    filter_sets = [
        QuerySearchScreenFilterSetDTO(
            filter_type="equals",
            field_name="modality",
            operator="eq",
            value="CT"
        ),
        QuerySearchScreenFilterSetDTO(
            filter_type="contains",
            field_name="description",
            operator="like",
            value="chest"
        )
    ]
    
    # Create advanced query
    advanced_query = QuerySearchScreenDTO(
        query_name="modality_search",
        query_filter_sets=filter_sets,
        optional_fields=["dicomName", "dicomCode", "primaryKey"]
    )
    
    result = client.search(advanced_query)
    if result:
        print(f"✅ Found {result.total} results")
        for i, item in enumerate(result.results[:3], 1):  # Show first 3 results
            print(f"  [{i}] {item.name}")
            print(f"      DICOM: {item.dicom_name}")
            print(f"      Code: {item.dicom_code}")
    else:
        print("❌ Advanced search failed")
    
    # Example 3: Empty search to see available data structure
    print("\n🔍 Example 3: Discovery Search")
    result = client.search_simple(
        query_name="discovery",
        filters={},  # No filters to see what's available
        optional_fields=["dicomName", "dicomCode", "primaryKey"]
    )
    
    if result:
        print(f"✅ Discovery found {result.total} total items")
        if result.results:
            print("Sample result structure:")
            sample = result.results[0]
            print(f"  name: {sample.name}")
            print(f"  code: {sample.code}")
            print(f"  dicomName: {sample.dicom_name}")
            print(f"  dicomCode: {sample.dicom_code}")
            print(f"  primaryKey: {sample.primary_key}")
            print(f"  active: {sample.active}")
    else:
        print("❌ Discovery search failed")

if __name__ == "__main__":
    main()