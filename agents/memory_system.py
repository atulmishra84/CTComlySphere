"""
Advanced Memory System for Healthcare Compliance AI Agent

This module provides persistent memory and context management capabilities:
- Long-term memory for learning from interactions
- Context retention across conversations
- Pattern recognition and knowledge accumulation
- Adaptive personalization based on user preferences
"""

import json
import sqlite3
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

from app import db
from models import AIAgent, ComplianceEvaluation


class MemoryType(Enum):
    """Types of memories stored by the agent"""
    CONVERSATION = "conversation"
    DECISION = "decision"
    PATTERN = "pattern"
    USER_PREFERENCE = "user_preference"
    KNOWLEDGE = "knowledge"
    EXPERIENCE = "experience"


class MemoryImportance(Enum):
    """Importance levels for memory prioritization"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Memory:
    """Individual memory item"""
    id: str
    memory_type: MemoryType
    content: Dict[str, Any]
    context: Dict[str, Any]
    importance: MemoryImportance
    created_at: datetime
    last_accessed: datetime
    access_count: int
    tags: List[str]
    related_memories: List[str]


class AgentMemorySystem:
    """
    Advanced memory system that provides the AI agent with:
    - Persistent storage of interactions and learnings
    - Context-aware memory retrieval
    - Pattern recognition and knowledge synthesis
    - User preference learning and adaptation
    """
    
    def __init__(self, database_path: str = "agent_memory.db"):
        self.logger = logging.getLogger(__name__)
        self.database_path = database_path
        
        # In-memory caches for performance
        self.conversation_context = {}
        self.active_patterns = {}
        self.user_profiles = {}
        
        # Memory management settings
        self.max_conversation_history = 1000
        self.memory_retention_days = 365
        self.cleanup_frequency_hours = 24
        
        # Initialize database
        self.initialize_database()
        
        # Load critical memories into cache
        self.load_critical_memories()
        
        self.logger.info("Agent Memory System initialized")
    
    def initialize_database(self):
        """Initialize SQLite database for persistent memory storage"""
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create memories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                content TEXT NOT NULL,
                context TEXT NOT NULL,
                importance TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed TEXT NOT NULL,
                access_count INTEGER DEFAULT 0,
                tags TEXT NOT NULL,
                related_memories TEXT
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memory_type ON memories(memory_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_importance ON memories(importance)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON memories(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tags ON memories(tags)')
        
        conn.commit()
        conn.close()
    
    def load_critical_memories(self):
        """Load critical memories into cache for fast access"""
        
        critical_memories = self.search_memories(
            importance=MemoryImportance.CRITICAL,
            limit=100
        )
        
        for memory in critical_memories:
            if memory.memory_type == MemoryType.USER_PREFERENCE:
                user_id = memory.context.get("user_id", "default")
                if user_id not in self.user_profiles:
                    self.user_profiles[user_id] = {}
                self.user_profiles[user_id].update(memory.content)
            
            elif memory.memory_type == MemoryType.PATTERN:
                pattern_key = memory.content.get("pattern_id")
                if pattern_key:
                    self.active_patterns[pattern_key] = memory.content
        
        self.logger.info(f"Loaded {len(critical_memories)} critical memories into cache")
    
    def store_memory(self, memory_type: MemoryType, content: Dict[str, Any], 
                    context: Dict[str, Any], importance: MemoryImportance = MemoryImportance.MEDIUM,
                    tags: List[str] = None) -> str:
        """Store a new memory in the system"""
        
        if tags is None:
            tags = []
        
        # Generate unique ID
        memory_id = self._generate_memory_id(content, context)
        
        # Create memory object
        memory = Memory(
            id=memory_id,
            memory_type=memory_type,
            content=content,
            context=context,
            importance=importance,
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow(),
            access_count=0,
            tags=tags,
            related_memories=[]
        )
        
        # Store in database
        self._store_memory_db(memory)
        
        # Update caches if critical
        if importance == MemoryImportance.CRITICAL:
            self._update_cache(memory)
        
        # Find and link related memories
        self._link_related_memories(memory)
        
        self.logger.debug(f"Stored memory: {memory_id} ({memory_type.value})")
        return memory_id
    
    def retrieve_memory(self, memory_id: str) -> Optional[Memory]:
        """Retrieve a specific memory by ID"""
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM memories WHERE id = ?
        ''', (memory_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            memory = self._row_to_memory(row)
            
            # Update access tracking
            memory.last_accessed = datetime.utcnow()
            memory.access_count += 1
            self._update_memory_access(memory_id)
            
            return memory
        
        return None
    
    def search_memories(self, memory_type: Optional[MemoryType] = None,
                       importance: Optional[MemoryImportance] = None,
                       tags: List[str] = None, content_query: str = None,
                       since: Optional[datetime] = None, limit: int = 50) -> List[Memory]:
        """Search memories based on various criteria"""
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Build query
        conditions = []
        params = []
        
        if memory_type:
            conditions.append("memory_type = ?")
            params.append(memory_type.value)
        
        if importance:
            conditions.append("importance = ?")
            params.append(importance.value)
        
        if since:
            conditions.append("created_at >= ?")
            params.append(since.isoformat())
        
        if tags:
            # Search for memories containing any of the specified tags
            tag_conditions = []
            for tag in tags:
                tag_conditions.append("tags LIKE ?")
                params.append(f"%{tag}%")
            if tag_conditions:
                conditions.append(f"({' OR '.join(tag_conditions)})")
        
        if content_query:
            conditions.append("content LIKE ?")
            params.append(f"%{content_query}%")
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        query = f'''
            SELECT * FROM memories 
            {where_clause}
            ORDER BY importance DESC, last_accessed DESC 
            LIMIT ?
        '''
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        memories = [self._row_to_memory(row) for row in rows]
        
        # Update access tracking for retrieved memories
        for memory in memories:
            self._update_memory_access(memory.id)
        
        return memories
    
    def get_conversation_context(self, user_id: str, conversation_id: str) -> Dict[str, Any]:
        """Get conversation context for maintaining dialogue continuity"""
        
        context_key = f"{user_id}_{conversation_id}"
        
        if context_key in self.conversation_context:
            return self.conversation_context[context_key]
        
        # Retrieve from database
        conversation_memories = self.search_memories(
            memory_type=MemoryType.CONVERSATION,
            tags=[f"user:{user_id}", f"conversation:{conversation_id}"],
            limit=20
        )
        
        context = {
            "user_id": user_id,
            "conversation_id": conversation_id,
            "recent_topics": [],
            "user_preferences": self.get_user_preferences(user_id),
            "conversation_history": []
        }
        
        # Build context from memories
        for memory in conversation_memories:
            if "topic" in memory.content:
                context["recent_topics"].append(memory.content["topic"])
            
            if "user_message" in memory.content:
                context["conversation_history"].append({
                    "timestamp": memory.created_at.isoformat(),
                    "user_message": memory.content["user_message"],
                    "agent_response": memory.content.get("agent_response", ""),
                    "intent": memory.content.get("intent", "")
                })
        
        # Cache for quick access
        self.conversation_context[context_key] = context
        
        return context
    
    def update_conversation_context(self, user_id: str, conversation_id: str,
                                  user_message: str, agent_response: str,
                                  intent: str = None, topic: str = None):
        """Update conversation context with new interaction"""
        
        # Store conversation memory
        content = {
            "user_message": user_message,
            "agent_response": agent_response,
            "intent": intent,
            "topic": topic
        }
        
        context = {
            "user_id": user_id,
            "conversation_id": conversation_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        tags = [f"user:{user_id}", f"conversation:{conversation_id}"]
        if topic:
            tags.append(f"topic:{topic}")
        if intent:
            tags.append(f"intent:{intent}")
        
        self.store_memory(
            memory_type=MemoryType.CONVERSATION,
            content=content,
            context=context,
            importance=MemoryImportance.MEDIUM,
            tags=tags
        )
        
        # Update cache
        context_key = f"{user_id}_{conversation_id}"
        if context_key in self.conversation_context:
            ctx = self.conversation_context[context_key]
            ctx["conversation_history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "user_message": user_message,
                "agent_response": agent_response,
                "intent": intent
            })
            
            if topic and topic not in ctx["recent_topics"]:
                ctx["recent_topics"].append(topic)
                # Keep only recent topics
                ctx["recent_topics"] = ctx["recent_topics"][-10:]
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences and personalization settings"""
        
        if user_id in self.user_profiles:
            return self.user_profiles[user_id]
        
        # Retrieve from database
        preference_memories = self.search_memories(
            memory_type=MemoryType.USER_PREFERENCE,
            tags=[f"user:{user_id}"],
            limit=50
        )
        
        preferences = {
            "communication_style": "professional",
            "detail_level": "moderate",
            "preferred_frameworks": [],
            "notification_preferences": {},
            "learning_style": "balanced"
        }
        
        # Aggregate preferences from memories
        for memory in preference_memories:
            preferences.update(memory.content)
        
        # Cache preferences
        self.user_profiles[user_id] = preferences
        
        return preferences
    
    def update_user_preferences(self, user_id: str, preference_updates: Dict[str, Any]):
        """Update user preferences based on observed behavior"""
        
        # Store preference memory
        content = preference_updates.copy()
        content["updated_at"] = datetime.utcnow().isoformat()
        
        context = {
            "user_id": user_id,
            "source": "behavior_analysis"
        }
        
        self.store_memory(
            memory_type=MemoryType.USER_PREFERENCE,
            content=content,
            context=context,
            importance=MemoryImportance.HIGH,
            tags=[f"user:{user_id}", "preferences"]
        )
        
        # Update cache
        if user_id in self.user_profiles:
            self.user_profiles[user_id].update(preference_updates)
        else:
            self.user_profiles[user_id] = preference_updates
    
    def store_decision_memory(self, decision_context: Dict[str, Any], 
                            decision_outcome: Dict[str, Any], 
                            effectiveness_score: float = None):
        """Store memory about agent decisions for learning"""
        
        content = {
            "decision_context": decision_context,
            "decision_outcome": decision_outcome,
            "effectiveness_score": effectiveness_score,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        context = {
            "agent_id": decision_context.get("agent_id"),
            "framework": decision_context.get("compliance_framework"),
            "decision_type": decision_outcome.get("action_taken")
        }
        
        tags = ["decision", "learning"]
        if context.get("framework"):
            tags.append(f"framework:{context['framework']}")
        if context.get("decision_type"):
            tags.append(f"action:{context['decision_type']}")
        
        importance = MemoryImportance.HIGH if effectiveness_score and effectiveness_score > 0.8 else MemoryImportance.MEDIUM
        
        self.store_memory(
            memory_type=MemoryType.DECISION,
            content=content,
            context=context,
            importance=importance,
            tags=tags
        )
    
    def find_similar_decisions(self, current_context: Dict[str, Any]) -> List[Memory]:
        """Find similar past decisions for guidance"""
        
        # Search for decision memories with similar context
        tags = ["decision"]
        
        if current_context.get("compliance_framework"):
            tags.append(f"framework:{current_context['compliance_framework']}")
        
        similar_decisions = self.search_memories(
            memory_type=MemoryType.DECISION,
            tags=tags,
            limit=10
        )
        
        # Rank by context similarity
        ranked_decisions = []
        for memory in similar_decisions:
            similarity_score = self._calculate_context_similarity(
                current_context, memory.content.get("decision_context", {})
            )
            if similarity_score > 0.5:  # Threshold for relevance
                ranked_decisions.append((memory, similarity_score))
        
        # Sort by similarity score
        ranked_decisions.sort(key=lambda x: x[1], reverse=True)
        
        return [decision[0] for decision in ranked_decisions]
    
    def learn_patterns(self, pattern_type: str, pattern_data: Dict[str, Any]):
        """Learn and store behavioral patterns"""
        
        pattern_id = f"{pattern_type}_{hashlib.md5(json.dumps(pattern_data, sort_keys=True).encode()).hexdigest()[:8]}"
        
        content = {
            "pattern_id": pattern_id,
            "pattern_type": pattern_type,
            "pattern_data": pattern_data,
            "confidence": pattern_data.get("confidence", 0.5),
            "occurrences": 1
        }
        
        context = {
            "learned_at": datetime.utcnow().isoformat(),
            "source": "pattern_analysis"
        }
        
        # Check if pattern already exists
        existing_patterns = self.search_memories(
            memory_type=MemoryType.PATTERN,
            content_query=pattern_id,
            limit=1
        )
        
        if existing_patterns:
            # Update existing pattern
            existing = existing_patterns[0]
            existing.content["occurrences"] += 1
            existing.content["confidence"] = min(1.0, existing.content["confidence"] + 0.1)
            self._update_memory_content(existing.id, existing.content)
        else:
            # Store new pattern
            self.store_memory(
                memory_type=MemoryType.PATTERN,
                content=content,
                context=context,
                importance=MemoryImportance.HIGH,
                tags=["pattern", pattern_type]
            )
        
        # Update cache
        self.active_patterns[pattern_id] = content
    
    def cleanup_old_memories(self):
        """Clean up old, low-importance memories to manage storage"""
        
        cutoff_date = datetime.utcnow() - timedelta(days=self.memory_retention_days)
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Delete old, low-importance memories
        cursor.execute('''
            DELETE FROM memories 
            WHERE created_at < ? AND importance = ? AND access_count < 5
        ''', (cutoff_date.isoformat(), MemoryImportance.LOW.value))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleaned up {deleted_count} old memories")
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get statistics about the memory system"""
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Total memories by type
        cursor.execute('''
            SELECT memory_type, COUNT(*) 
            FROM memories 
            GROUP BY memory_type
        ''')
        type_counts = dict(cursor.fetchall())
        
        # Total memories by importance
        cursor.execute('''
            SELECT importance, COUNT(*) 
            FROM memories 
            GROUP BY importance
        ''')
        importance_counts = dict(cursor.fetchall())
        
        # Recent activity
        recent_date = (datetime.utcnow() - timedelta(days=7)).isoformat()
        cursor.execute('''
            SELECT COUNT(*) 
            FROM memories 
            WHERE created_at >= ?
        ''', (recent_date,))
        recent_memories = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_memories": sum(type_counts.values()),
            "memories_by_type": type_counts,
            "memories_by_importance": importance_counts,
            "recent_activity": recent_memories,
            "cached_user_profiles": len(self.user_profiles),
            "active_patterns": len(self.active_patterns),
            "conversation_contexts": len(self.conversation_context)
        }
    
    def _generate_memory_id(self, content: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Generate unique ID for memory"""
        combined = {**content, **context, "timestamp": datetime.utcnow().isoformat()}
        content_hash = hashlib.md5(json.dumps(combined, sort_keys=True).encode()).hexdigest()
        return f"mem_{content_hash[:16]}"
    
    def _store_memory_db(self, memory: Memory):
        """Store memory in database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO memories 
            (id, memory_type, content, context, importance, created_at, last_accessed, access_count, tags, related_memories)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            memory.id,
            memory.memory_type.value,
            json.dumps(memory.content),
            json.dumps(memory.context),
            memory.importance.value,
            memory.created_at.isoformat(),
            memory.last_accessed.isoformat(),
            memory.access_count,
            json.dumps(memory.tags),
            json.dumps(memory.related_memories)
        ))
        
        conn.commit()
        conn.close()
    
    def _row_to_memory(self, row) -> Memory:
        """Convert database row to Memory object"""
        return Memory(
            id=row[0],
            memory_type=MemoryType(row[1]),
            content=json.loads(row[2]),
            context=json.loads(row[3]),
            importance=MemoryImportance(row[4]),
            created_at=datetime.fromisoformat(row[5]),
            last_accessed=datetime.fromisoformat(row[6]),
            access_count=row[7],
            tags=json.loads(row[8]),
            related_memories=json.loads(row[9]) if row[9] else []
        )
    
    def _update_memory_access(self, memory_id: str):
        """Update memory access tracking"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE memories 
            SET last_accessed = ?, access_count = access_count + 1
            WHERE id = ?
        ''', (datetime.utcnow().isoformat(), memory_id))
        
        conn.commit()
        conn.close()
    
    def _update_memory_content(self, memory_id: str, new_content: Dict[str, Any]):
        """Update memory content"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE memories 
            SET content = ?, last_accessed = ?
            WHERE id = ?
        ''', (json.dumps(new_content), datetime.utcnow().isoformat(), memory_id))
        
        conn.commit()
        conn.close()
    
    def _update_cache(self, memory: Memory):
        """Update in-memory caches with new memory"""
        if memory.memory_type == MemoryType.USER_PREFERENCE:
            user_id = memory.context.get("user_id", "default")
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = {}
            self.user_profiles[user_id].update(memory.content)
        
        elif memory.memory_type == MemoryType.PATTERN:
            pattern_id = memory.content.get("pattern_id")
            if pattern_id:
                self.active_patterns[pattern_id] = memory.content
    
    def _link_related_memories(self, memory: Memory):
        """Find and link related memories"""
        # Simple implementation - could be enhanced with ML similarity
        related_memories = self.search_memories(
            memory_type=memory.memory_type,
            tags=memory.tags[:2],  # Use first 2 tags for similarity
            limit=5
        )
        
        # Link memories that share similar tags or context
        for related in related_memories:
            if related.id != memory.id:
                shared_tags = set(memory.tags) & set(related.tags)
                if len(shared_tags) >= 2:  # At least 2 shared tags
                    if memory.id not in related.related_memories:
                        related.related_memories.append(memory.id)
                        self._update_related_memories(related.id, related.related_memories)
                    
                    if related.id not in memory.related_memories:
                        memory.related_memories.append(related.id)
    
    def _update_related_memories(self, memory_id: str, related_memories: List[str]):
        """Update related memories list in database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE memories 
            SET related_memories = ?
            WHERE id = ?
        ''', (json.dumps(related_memories), memory_id))
        
        conn.commit()
        conn.close()
    
    def _calculate_context_similarity(self, context1: Dict[str, Any], 
                                    context2: Dict[str, Any]) -> float:
        """Calculate similarity between two contexts"""
        if not context1 or not context2:
            return 0.0
        
        # Simple similarity based on shared keys and values
        shared_keys = set(context1.keys()) & set(context2.keys())
        if not shared_keys:
            return 0.0
        
        matching_values = 0
        for key in shared_keys:
            if context1[key] == context2[key]:
                matching_values += 1
        
        return matching_values / len(shared_keys)


# Global instance
agent_memory_system = AgentMemorySystem()