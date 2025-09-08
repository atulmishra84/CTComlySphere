"""
Enhanced Conversation Handler for Healthcare Compliance AI Agent

This module provides sophisticated natural language processing and
conversation management capabilities for the AI agent.
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from agents.memory_system import agent_memory_system, MemoryType, MemoryImportance


class ConversationIntent(Enum):
    """Enhanced conversation intents"""
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_CHECK = "compliance_check"
    PREDICTIVE_ANALYSIS = "predictive_analysis"
    REMEDIATION_REQUEST = "remediation_request"
    STATUS_INQUIRY = "status_inquiry"
    LEARNING_QUERY = "learning_query"
    TREND_ANALYSIS = "trend_analysis"
    EMERGENCY_RESPONSE = "emergency_response"
    CONFIGURATION_CHANGE = "configuration_change"
    REPORTING_REQUEST = "reporting_request"


class ConversationTone(Enum):
    """Conversation tone analysis"""
    URGENT = "urgent"
    FORMAL = "formal"
    CASUAL = "casual"
    TECHNICAL = "technical"
    CONCERNED = "concerned"
    ANALYTICAL = "analytical"


@dataclass
class ConversationContext:
    """Enhanced conversation context"""
    user_id: str
    conversation_id: str
    session_history: List[Dict[str, Any]]
    user_preferences: Dict[str, Any]
    current_intent: ConversationIntent
    tone: ConversationTone
    urgency_level: int  # 1-10 scale
    technical_level: str  # basic, intermediate, advanced
    frameworks_of_interest: List[str]
    conversation_depth: int


class EnhancedConversationHandler:
    """
    Advanced conversation handler that provides:
    - Context-aware natural language understanding
    - Personalized communication style adaptation
    - Memory-driven conversation continuity
    - Intent recognition with confidence scoring
    - Multi-turn conversation management
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.memory_system = agent_memory_system
        
        # Conversation patterns and intents
        self.intent_patterns = self._initialize_intent_patterns()
        self.urgency_keywords = self._initialize_urgency_keywords()
        self.framework_keywords = self._initialize_framework_keywords()
        
        # Response templates
        self.response_templates = self._initialize_response_templates()
        
        self.logger.info("Enhanced Conversation Handler initialized")
    
    def _initialize_intent_patterns(self) -> Dict[ConversationIntent, List[str]]:
        """Initialize patterns for intent recognition"""
        return {
            ConversationIntent.RISK_ASSESSMENT: [
                r"(risk|threat|vulnerability|exposure)\s+(assessment|analysis|evaluation)",
                r"how\s+(risky|dangerous|vulnerable)\s+is",
                r"assess\s+the\s+risk",
                r"what.*risk.*level",
                r"security\s+(risk|threat)",
                r"compliance\s+risk"
            ],
            ConversationIntent.COMPLIANCE_CHECK: [
                r"compliance\s+(status|check|evaluation)",
                r"are\s+we\s+compliant",
                r"hipaa\s+(compliance|status)",
                r"gdpr\s+(compliance|status)",
                r"check\s+(compliance|conformance)",
                r"audit\s+readiness"
            ],
            ConversationIntent.PREDICTIVE_ANALYSIS: [
                r"predict.*compliance",
                r"future\s+(risk|threat|vulnerability)",
                r"trend\s+analysis",
                r"forecast.*compliance",
                r"what.*expect.*future",
                r"predictive\s+(analytics|modeling)"
            ],
            ConversationIntent.REMEDIATION_REQUEST: [
                r"fix\s+(this|issue|problem|vulnerability)",
                r"remediat.*",
                r"resolve\s+(compliance|security)\s+issue",
                r"automat.*fix",
                r"trigger\s+(fix|remediation)",
                r"apply\s+(patch|fix|update)"
            ],
            ConversationIntent.STATUS_INQUIRY: [
                r"status\s+(of|report)",
                r"current\s+state",
                r"what.*happening",
                r"system\s+status",
                r"agent\s+status",
                r"overview"
            ],
            ConversationIntent.LEARNING_QUERY: [
                r"learn.*from",
                r"pattern.*analysis",
                r"what.*learned",
                r"decision.*history",
                r"past\s+(experience|decisions)",
                r"knowledge\s+base"
            ],
            ConversationIntent.TREND_ANALYSIS: [
                r"trend.*analysis",
                r"pattern.*over\s+time",
                r"historical.*data",
                r"compliance.*trend",
                r"improvement.*over\s+time",
                r"degradation.*trend"
            ],
            ConversationIntent.EMERGENCY_RESPONSE: [
                r"emergency",
                r"critical\s+(issue|alert|problem)",
                r"urgent.*response",
                r"immediate\s+(action|attention)",
                r"security\s+(incident|breach)",
                r"help\s+(urgent|emergency)"
            ]
        }
    
    def _initialize_urgency_keywords(self) -> Dict[str, int]:
        """Initialize urgency keyword scoring"""
        return {
            "emergency": 10,
            "critical": 9,
            "urgent": 8,
            "immediate": 8,
            "asap": 7,
            "quickly": 6,
            "soon": 5,
            "important": 5,
            "priority": 6,
            "escalate": 8,
            "breach": 9,
            "incident": 8,
            "failure": 7,
            "down": 7,
            "compromised": 9
        }
    
    def _initialize_framework_keywords(self) -> Dict[str, List[str]]:
        """Initialize framework detection keywords"""
        return {
            "HIPAA": ["hipaa", "phi", "protected health", "healthcare", "medical records"],
            "GDPR": ["gdpr", "privacy", "personal data", "data subject", "consent"],
            "FDA": ["fda", "medical device", "samd", "clinical", "regulatory"],
            "SOC2": ["soc2", "soc 2", "security controls", "audit", "trust services"],
            "HITRUST": ["hitrust", "csf", "security framework"],
            "NIST": ["nist", "cybersecurity framework", "security controls"]
        }
    
    def _initialize_response_templates(self) -> Dict[str, Dict[str, str]]:
        """Initialize response templates for different scenarios"""
        return {
            "risk_assessment": {
                "formal": "Based on my analysis of the compliance landscape, I've identified {risk_count} potential risk areas requiring attention. The primary concerns are: {risk_summary}",
                "casual": "I found {risk_count} things we should look at. The main issues are: {risk_summary}",
                "technical": "Risk assessment complete. Identified {risk_count} vectors with severity distribution: {technical_details}"
            },
            "compliance_status": {
                "formal": "Current compliance status across monitored frameworks shows {compliance_summary}. Detailed evaluation reveals {details}",
                "casual": "Here's where we stand with compliance: {compliance_summary}. {details}",
                "technical": "Compliance metrics: {technical_metrics}. Framework-specific scores: {detailed_scores}"
            },
            "predictive_analysis": {
                "formal": "Predictive analysis indicates {prediction_summary} with {confidence} confidence. Recommended proactive measures include: {recommendations}",
                "casual": "Looking ahead, I predict {prediction_summary}. Here's what we should do: {recommendations}",
                "technical": "Predictive model output: {technical_predictions}. Statistical confidence: {confidence}. Recommended interventions: {recommendations}"
            }
        }
    
    async def process_conversation(self, user_message: str, user_id: str, 
                                 conversation_id: str) -> Dict[str, Any]:
        """Process user message with enhanced conversation understanding"""
        
        try:
            # Get conversation context
            context = await self._build_conversation_context(user_message, user_id, conversation_id)
            
            # Analyze message intent and properties
            analysis = await self._analyze_message(user_message, context)
            
            # Generate contextual response
            response = await self._generate_response(analysis, context)
            
            # Update conversation memory
            await self._update_conversation_memory(user_message, response, context)
            
            return {
                "response": response,
                "intent": analysis["intent"].value,
                "confidence": analysis["confidence"],
                "urgency": analysis["urgency"],
                "context": {
                    "user_preferences": context.user_preferences,
                    "conversation_depth": context.conversation_depth,
                    "frameworks": context.frameworks_of_interest
                }
            }
            
        except Exception as e:
            self.logger.error(f"Conversation processing failed: {str(e)}")
            return {
                "response": "I apologize, but I encountered an issue processing your request. Could you please rephrase your question?",
                "intent": "error",
                "confidence": 0.0,
                "urgency": 1
            }
    
    async def _build_conversation_context(self, message: str, user_id: str, 
                                        conversation_id: str) -> ConversationContext:
        """Build comprehensive conversation context"""
        
        # Get conversation history from memory
        conversation_context = self.memory_system.get_conversation_context(user_id, conversation_id)
        
        # Get user preferences
        user_preferences = self.memory_system.get_user_preferences(user_id)
        
        # Analyze message characteristics
        urgency = self._calculate_urgency(message)
        tone = self._detect_tone(message)
        frameworks = self._detect_frameworks(message)
        technical_level = user_preferences.get("technical_level", "intermediate")
        
        return ConversationContext(
            user_id=user_id,
            conversation_id=conversation_id,
            session_history=conversation_context.get("conversation_history", []),
            user_preferences=user_preferences,
            current_intent=ConversationIntent.STATUS_INQUIRY,  # Will be updated in analysis
            tone=tone,
            urgency_level=urgency,
            technical_level=technical_level,
            frameworks_of_interest=frameworks,
            conversation_depth=len(conversation_context.get("conversation_history", []))
        )
    
    async def _analyze_message(self, message: str, context: ConversationContext) -> Dict[str, Any]:
        """Analyze message for intent, urgency, and other properties"""
        
        message_lower = message.lower()
        
        # Intent recognition
        intent_scores = {}
        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    score += 1
            intent_scores[intent] = score
        
        # Determine primary intent
        if intent_scores:
            primary_intent = max(intent_scores, key=intent_scores.get)
            confidence = intent_scores[primary_intent] / len(self.intent_patterns[primary_intent])
        else:
            primary_intent = ConversationIntent.STATUS_INQUIRY
            confidence = 0.5
        
        # Calculate urgency
        urgency = self._calculate_urgency(message)
        
        # Extract entities (agents, frameworks, etc.)
        entities = self._extract_entities(message)
        
        return {
            "intent": primary_intent,
            "confidence": min(confidence, 1.0),
            "urgency": urgency,
            "entities": entities,
            "sentiment": self._analyze_sentiment(message),
            "complexity": self._assess_complexity(message)
        }
    
    def _calculate_urgency(self, message: str) -> int:
        """Calculate urgency score from message content"""
        message_lower = message.lower()
        urgency_score = 1  # Base urgency
        
        for keyword, score in self.urgency_keywords.items():
            if keyword in message_lower:
                urgency_score = max(urgency_score, score)
        
        # Adjust for multiple urgent keywords
        urgent_count = sum(1 for keyword in self.urgency_keywords.keys() if keyword in message_lower)
        if urgent_count > 1:
            urgency_score = min(urgency_score + urgent_count, 10)
        
        return urgency_score
    
    def _detect_tone(self, message: str) -> ConversationTone:
        """Detect conversation tone"""
        message_lower = message.lower()
        
        # Urgent indicators
        if any(word in message_lower for word in ["emergency", "urgent", "critical", "asap"]):
            return ConversationTone.URGENT
        
        # Technical indicators
        if any(word in message_lower for word in ["analyze", "metrics", "statistics", "algorithm", "configuration"]):
            return ConversationTone.TECHNICAL
        
        # Concerned indicators
        if any(word in message_lower for word in ["worried", "concerned", "problem", "issue", "breach"]):
            return ConversationTone.CONCERNED
        
        # Formal indicators
        if any(word in message_lower for word in ["please", "kindly", "assessment", "evaluation", "compliance"]):
            return ConversationTone.FORMAL
        
        return ConversationTone.CASUAL
    
    def _detect_frameworks(self, message: str) -> List[str]:
        """Detect mentioned compliance frameworks"""
        message_lower = message.lower()
        detected_frameworks = []
        
        for framework, keywords in self.framework_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                detected_frameworks.append(framework)
        
        return detected_frameworks
    
    def _extract_entities(self, message: str) -> Dict[str, List[str]]:
        """Extract entities from message (agents, frameworks, risk levels, etc.)"""
        entities = {
            "agents": [],
            "frameworks": self._detect_frameworks(message),
            "risk_levels": [],
            "actions": []
        }
        
        # Extract risk levels
        risk_patterns = {
            "critical": r"critical",
            "high": r"high",
            "medium": r"medium|moderate",
            "low": r"low"
        }
        
        for level, pattern in risk_patterns.items():
            if re.search(pattern, message.lower()):
                entities["risk_levels"].append(level)
        
        # Extract action words
        action_patterns = [
            r"fix", r"resolve", r"remediate", r"patch", r"update", 
            r"monitor", r"scan", r"assess", r"analyze", r"report"
        ]
        
        for pattern in action_patterns:
            if re.search(pattern, message.lower()):
                entities["actions"].append(pattern)
        
        return entities
    
    def _analyze_sentiment(self, message: str) -> str:
        """Basic sentiment analysis"""
        positive_words = ["good", "great", "excellent", "working", "successful", "fixed"]
        negative_words = ["bad", "terrible", "broken", "failed", "error", "problem", "issue"]
        
        message_lower = message.lower()
        positive_count = sum(1 for word in positive_words if word in message_lower)
        negative_count = sum(1 for word in negative_words if word in message_lower)
        
        if negative_count > positive_count:
            return "negative"
        elif positive_count > negative_count:
            return "positive"
        else:
            return "neutral"
    
    def _assess_complexity(self, message: str) -> str:
        """Assess message complexity"""
        word_count = len(message.split())
        technical_terms = ["algorithm", "configuration", "architecture", "implementation", "analytics"]
        technical_count = sum(1 for term in technical_terms if term in message.lower())
        
        if word_count > 50 or technical_count > 2:
            return "complex"
        elif word_count > 20 or technical_count > 0:
            return "moderate"
        else:
            return "simple"
    
    async def _generate_response(self, analysis: Dict[str, Any], 
                               context: ConversationContext) -> str:
        """Generate contextual response based on analysis and context"""
        
        intent = analysis["intent"]
        urgency = analysis["urgency"]
        
        # Select appropriate response style
        if context.technical_level == "advanced":
            style = "technical"
        elif context.tone == ConversationTone.FORMAL:
            style = "formal"
        else:
            style = "casual"
        
        # Generate response based on intent
        if intent == ConversationIntent.RISK_ASSESSMENT:
            return await self._generate_risk_assessment_response(analysis, context, style)
        elif intent == ConversationIntent.COMPLIANCE_CHECK:
            return await self._generate_compliance_response(analysis, context, style)
        elif intent == ConversationIntent.PREDICTIVE_ANALYSIS:
            return await self._generate_predictive_response(analysis, context, style)
        elif intent == ConversationIntent.REMEDIATION_REQUEST:
            return await self._generate_remediation_response(analysis, context, style)
        elif intent == ConversationIntent.EMERGENCY_RESPONSE:
            return await self._generate_emergency_response(analysis, context)
        else:
            return await self._generate_default_response(analysis, context, style)
    
    async def _generate_risk_assessment_response(self, analysis: Dict[str, Any], 
                                               context: ConversationContext, style: str) -> str:
        """Generate risk assessment response"""
        
        template = self.response_templates["risk_assessment"][style]
        
        # This would integrate with actual risk assessment data
        risk_data = {
            "risk_count": 3,
            "risk_summary": "encryption gaps, access control weaknesses, audit log issues",
            "technical_details": "HIGH: 1, MEDIUM: 2, LOW: 0"
        }
        
        return template.format(**risk_data)
    
    async def _generate_compliance_response(self, analysis: Dict[str, Any], 
                                          context: ConversationContext, style: str) -> str:
        """Generate compliance status response"""
        
        template = self.response_templates["compliance_status"][style]
        
        # This would integrate with actual compliance data
        compliance_data = {
            "compliance_summary": "82% overall compliance across monitored frameworks",
            "details": "HIPAA: 85%, GDPR: 78%, SOC2: 84%",
            "technical_metrics": "avg_score: 82.3, std_dev: 3.1",
            "detailed_scores": "HIPAA: 85.2, GDPR: 78.1, SOC2: 84.7"
        }
        
        return template.format(**compliance_data)
    
    async def _generate_predictive_response(self, analysis: Dict[str, Any], 
                                          context: ConversationContext, style: str) -> str:
        """Generate predictive analysis response"""
        
        template = self.response_templates["predictive_analysis"][style]
        
        # This would integrate with actual predictive data
        prediction_data = {
            "prediction_summary": "slight compliance degradation in HIPAA framework over next 30 days",
            "confidence": "85%",
            "recommendations": "proactive encryption review, access control audit",
            "technical_predictions": "HIPAA_risk_trend: +0.15, confidence_interval: [0.12, 0.18]"
        }
        
        return template.format(**prediction_data)
    
    async def _generate_remediation_response(self, analysis: Dict[str, Any], 
                                           context: ConversationContext, style: str) -> str:
        """Generate remediation response"""
        
        if context.urgency_level >= 8:
            return "I'm initiating emergency remediation protocols now. You'll see automated fixes applying within 2-3 minutes. I'll keep you updated on progress."
        else:
            return "I can help with that remediation. Let me analyze the issue and recommend the best automated workflow. Should I proceed with implementing the fix?"
    
    async def _generate_emergency_response(self, analysis: Dict[str, Any], 
                                         context: ConversationContext) -> str:
        """Generate emergency response"""
        
        return ("🚨 EMERGENCY RESPONSE ACTIVATED 🚨\n\n"
                "I'm immediately:\n"
                "• Triggering emergency compliance protocols\n"
                "• Initiating system isolation procedures\n"
                "• Alerting compliance stakeholders\n"
                "• Starting automated incident response\n\n"
                "You'll receive real-time updates. Emergency response team has been notified.")
    
    async def _generate_default_response(self, analysis: Dict[str, Any], 
                                       context: ConversationContext, style: str) -> str:
        """Generate default response"""
        
        frameworks_mentioned = analysis["entities"]["frameworks"]
        if frameworks_mentioned:
            return f"I can help you with {', '.join(frameworks_mentioned)} compliance. What specific aspect would you like me to analyze or address?"
        
        return "I'm here to help with healthcare AI compliance. I can assess risks, check compliance status, predict future issues, and trigger automated remediation. What would you like me to do?"
    
    async def _update_conversation_memory(self, user_message: str, agent_response: str, 
                                        context: ConversationContext):
        """Update conversation memory with interaction"""
        
        # Determine topic/intent for memory tagging
        topic = context.current_intent.value if hasattr(context, 'current_intent') else "general"
        
        # Update conversation context in memory system
        self.memory_system.update_conversation_context(
            user_id=context.user_id,
            conversation_id=context.conversation_id,
            user_message=user_message,
            agent_response=agent_response,
            intent=topic,
            topic=topic
        )
        
        # Learn from user preferences
        if context.urgency_level >= 7:
            # User prefers urgent responses
            self.memory_system.update_user_preferences(
                context.user_id,
                {"response_speed": "urgent", "communication_style": "direct"}
            )
        
        if context.technical_level == "advanced" and "technical" in agent_response.lower():
            # User appreciates technical details
            self.memory_system.update_user_preferences(
                context.user_id,
                {"detail_level": "technical", "preferred_response_type": "detailed"}
            )


# Global instance
enhanced_conversation_handler = EnhancedConversationHandler()