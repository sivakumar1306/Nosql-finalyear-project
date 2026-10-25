"""
Database configuration and connection management.
"""

import os
from typing import Optional
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import gridfs
from bson import ObjectId
from contextlib import contextmanager

from models.mongodb_indexes import create_indexes


class DatabaseManager:
    """Manages MongoDB connections and provides database utilities."""
    
    def __init__(self, connection_string: Optional[str] = None, db_name: str = "anomaly_detection"):
        """
        Initialize database manager.
        
        Args:
            connection_string: MongoDB connection string
            db_name: Database name
        """
        self.connection_string = connection_string or os.getenv(
            "MONGODB_URI", 
            "mongodb://localhost:27017/"
        )
        self.db_name = db_name
        self.client: Optional[MongoClient] = None
        self.db = None
        self.gridfs = None
        
    def connect(self, max_pool_size: int = 100, timeout_ms: int = 5000):
        """
        Connect to MongoDB database.
        
        Args:
            max_pool_size: Maximum connection pool size
            timeout_ms: Connection timeout in milliseconds
            
        Returns:
            bool: True if connection successful
        """
        try:
            self.client = MongoClient(
                self.connection_string,
                maxPoolSize=max_pool_size,
                serverSelectionTimeoutMS=timeout_ms
            )
            
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.gridfs = gridfs.GridFS(self.db)
            
            print(f"Connected to MongoDB database: {self.db_name}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"Failed to connect to MongoDB: {e}")
            self.client = None
            self.db = None
            self.gridfs = None
            return False
    
    def disconnect(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            self.gridfs = None
            print("Disconnected from MongoDB")
    
    def ensure_indexes(self):
        """Create all necessary indexes."""
        if self.db is None:
            raise RuntimeError("Database not connected")
        
        return create_indexes(self.db)
    
    def get_collection(self, collection_name: str):
        """
        Get a MongoDB collection.
        
        Args:
            collection_name: Name of the collection
            
        Returns:
            MongoDB collection instance
        """
        if self.db is None:
            raise RuntimeError("Database not connected")
        
        return self.db[collection_name]
    
    def save_model_to_gridfs(self, model_bytes: bytes, filename: str, metadata: dict = None) -> str:
        """
        Save machine learning model to GridFS.
        
        Args:
            model_bytes: Model as bytes
            filename: Name for the file
            metadata: Additional metadata
            
        Returns:
            GridFS file ID
        """
        if self.gridfs is None:
            raise RuntimeError("GridFS not available")
        
        file_id = self.gridfs.put(
            model_bytes,
            filename=filename,
            metadata=metadata or {}
        )
        return str(file_id)
    
    def load_model_from_gridfs(self, file_id: str) -> bytes:
        """
        Load machine learning model from GridFS.
        
        Args:
            file_id: GridFS file ID
            
        Returns:
            Model as bytes
        """
        if self.gridfs is None:
            raise RuntimeError("GridFS not available")
        
        return self.gridfs.get(ObjectId(file_id)).read()
    
    def delete_model_from_gridfs(self, file_id: str) -> bool:
        """
        Delete machine learning model from GridFS.
        
        Args:
            file_id: GridFS file ID
            
        Returns:
            True if deleted successfully
        """
        if self.gridfs is None:
            raise RuntimeError("GridFS not available")
        
        try:
            self.gridfs.delete(ObjectId(file_id))
            return True
        except Exception as e:
            print(f"Failed to delete model from GridFS: {e}")
            return False
    
    def get_database_stats(self) -> dict:
        """
        Get database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        if self.db is None:
            raise RuntimeError("Database not connected")
        
        stats = {
            "database_name": self.db_name,
            "collections": {},
            "connection_status": "connected" if self.client else "disconnected"
        }
        
        # Get collection statistics
        for collection_name in self.db.list_collection_names():
            try:
                collection = self.db[collection_name]
                stats["collections"][collection_name] = {
                    "count": collection.count_documents({}),
                    "indexes": list(collection.index_information().keys())
                }
            except Exception as e:
                stats["collections"][collection_name] = {"error": str(e)}
        
        return stats
    
    @contextmanager
    def session(self):
        """Context manager for database session."""
        if not self.client:
            self.connect()
        
        try:
            yield self
        finally:
            # We don't disconnect in the context manager to allow connection reuse
            pass


# Global database instance
db_manager = DatabaseManager()


def init_database():
    """Initialize database connection and indexes."""
    if db_manager.connect():
        db_manager.ensure_indexes()
        return True
    return False


def get_db():
    """Get database instance."""
    if db_manager.db is None:
        init_database()
    return db_manager.db


def get_gridfs():
    """Get GridFS instance."""
    if db_manager.gridfs is None:
        init_database()
    return db_manager.gridfs