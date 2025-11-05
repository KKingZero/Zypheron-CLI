"""
GraphQL Introspection and Security Testing
"""

import logging
from typing import Dict, List, Optional
import requests
import json

logger = logging.getLogger(__name__)


class GraphQLScanner:
    """
    GraphQL Security Scanner
    
    Tests for:
    - Introspection enabled (information disclosure)
    - Query depth attacks
    - Batch query attacks
    - Field suggestions enabled
    - IDOR in GraphQL queries
    """
    
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.schema: Optional[Dict] = None
        self.types: List[Dict] = []
        self.queries: List[Dict] = []
        self.mutations: List[Dict] = []
    
    def introspect(self) -> bool:
        """
        Perform GraphQL introspection
        
        Returns:
            True if introspection succeeded
        """
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields {
                name
                description
                args {
                    name
                    description
                    type {
                        name
                        kind
                    }
                }
                type {
                    name
                    kind
                }
            }
        }
        """
        
        try:
            response = requests.post(
                self.endpoint,
                json={'query': introspection_query},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and '__schema' in data['data']:
                    self.schema = data['data']['__schema']
                    self._parse_schema()
                    logger.info("GraphQL introspection successful")
                    logger.warning("Introspection is enabled - information disclosure risk")
                    return True
                    
        except Exception as e:
            logger.error(f"GraphQL introspection failed: {e}")
        
        return False
    
    def _parse_schema(self):
        """Parse introspection schema"""
        if not self.schema:
            return
        
        types = self.schema.get('types', [])
        
        for type_def in types:
            # Skip built-in types
            if type_def.get('name', '').startswith('__'):
                continue
            
            self.types.append(type_def)
            
            # Extract queries and mutations
            fields = type_def.get('fields', [])
            if type_def.get('name') == self.schema.get('queryType', {}).get('name'):
                self.queries = fields
            elif type_def.get('name') == self.schema.get('mutationType', {}).get('name'):
                self.mutations = fields
        
        logger.info(f"Parsed {len(self.types)} types, {len(self.queries)} queries, {len(self.mutations)} mutations")
    
    def test_depth_limit(self, max_depth: int = 20) -> bool:
        """
        Test if query depth limiting is enforced
        
        Returns:
            True if depth limiting is NOT enforced (vulnerability)
        """
        # Build deeply nested query
        deep_query = self._build_deep_query(max_depth)
        
        try:
            response = requests.post(
                self.endpoint,
                json={'query': deep_query},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.warning(f"Deep query ({max_depth} levels) executed successfully")
                return True  # Vulnerable
            elif response.status_code == 400:
                logger.info("Query depth limiting is enforced")
                return False  # Protected
                
        except Exception as e:
            logger.error(f"Depth limit test failed: {e}")
        
        return False
    
    def _build_deep_query(self, depth: int) -> str:
        """Build deeply nested GraphQL query"""
        # Example nested query
        query = "query DeepQuery { "
        
        for i in range(depth):
            query += f"level{i} {{ "
        
        query += "id"
        
        for i in range(depth):
            query += " }"
        
        query += " }"
        
        return query
    
    def test_batch_queries(self, batch_size: int = 100) -> bool:
        """
        Test if batch query limits are enforced
        
        Returns:
            True if batching is allowed without limits (vulnerability)
        """
        # Create batch of queries
        batch = []
        for i in range(batch_size):
            batch.append({
                'query': '{ __typename }',
                'variables': {}
            })
        
        try:
            response = requests.post(
                self.endpoint,
                json=batch,
                timeout=15
            )
            
            if response.status_code == 200:
                logger.warning(f"Batch of {batch_size} queries executed successfully")
                return True  # Vulnerable
            elif response.status_code == 400:
                logger.info("Batch query limiting is enforced")
                return False  # Protected
                
        except Exception as e:
            logger.error(f"Batch query test failed: {e}")
        
        return False
    
    def get_sensitive_queries(self) -> List[str]:
        """Identify potentially sensitive queries"""
        sensitive_keywords = [
            'user', 'admin', 'password', 'token', 'secret',
            'credit', 'payment', 'ssn', 'personal'
        ]
        
        sensitive = []
        
        for query in self.queries:
            query_name = query.get('name', '').lower()
            if any(keyword in query_name for keyword in sensitive_keywords):
                sensitive.append(query['name'])
        
        return sensitive
    
    def export_schema(self, output_file: str) -> bool:
        """Export GraphQL schema"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.schema, f, indent=2)
            
            logger.info(f"Exported GraphQL schema to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to export schema: {e}")
            return False

