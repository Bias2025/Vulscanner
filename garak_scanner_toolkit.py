#!/usr/bin/env python3
"""
Comprehensive Garak LLM Security Scanner Toolkit
===============================================

A sophisticated toolkit for conducting comprehensive security assessments of Large Language Models (LLMs)
using the Garak vulnerability scanner. This toolkit integrates all available probes and provides advanced
scanning capabilities for identifying threats and vulnerabilities.

Author: Isi Idemudia
License: Apache 2.0
Requirements: garak, python>=3.10
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import subprocess
import yaml
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('garak_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ScanCategory(Enum):
    """Security scan categories based on threat types"""
    JAILBREAKS = "jailbreaks"
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    TOXICITY = "toxicity"
    MALWARE = "malware"
    HALLUCINATION = "hallucination"
    ENCODING = "encoding"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ProbeConfig:
    """Configuration for individual probes"""
    name: str
    category: str
    description: str
    severity: SeverityLevel
    enabled: bool = True
    custom_params: Optional[Dict] = None

@dataclass
class ScanConfig:
    """Comprehensive scan configuration"""
    target_model: str
    model_type: str
    scan_categories: List[ScanCategory]
    output_dir: str
    report_prefix: str
    max_generations: int = 10
    timeout: int = 3600
    parallel_probes: int = 1
    custom_probes: Optional[List[str]] = None
    exclude_probes: Optional[List[str]] = None
    api_keys: Optional[Dict[str, str]] = None

class GarakProbeRegistry:
    """Registry of all available Garak probes organized by category"""
    
    def __init__(self):
        self.probes = self._initialize_probes()
    
    def _initialize_probes(self) -> Dict[str, List[ProbeConfig]]:
        """Initialize the comprehensive probe registry"""
        return {
            "jailbreaks": [
                ProbeConfig("dan.Dan_11_0", "jailbreaks", "DAN 11.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_10_0", "jailbreaks", "DAN 10.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_9_0", "jailbreaks", "DAN 9.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_8_0", "jailbreaks", "DAN 8.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_7_0", "jailbreaks", "DAN 7.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_6_2", "jailbreaks", "DAN 6.2 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.Dan_6_0", "jailbreaks", "DAN 6.0 jailbreak attempt", SeverityLevel.HIGH),
                ProbeConfig("dan.AntiDAN", "jailbreaks", "Anti-DAN jailbreak technique", SeverityLevel.HIGH),
                ProbeConfig("dan.AutoDAN", "jailbreaks", "Automated DAN jailbreak", SeverityLevel.CRITICAL),
                ProbeConfig("dan.AutoDANCached", "jailbreaks", "Cached AutoDAN attacks", SeverityLevel.CRITICAL),
                ProbeConfig("dan.ChatGPT_Developer_Mode_v2", "jailbreaks", "Developer Mode jailbreak v2", SeverityLevel.HIGH),
                ProbeConfig("dan.ChatGPT_Developer_Mode_RANTI", "jailbreaks", "RANTI Developer Mode jailbreak", SeverityLevel.HIGH),
                ProbeConfig("dan.ChatGPT_Image_Markdown", "jailbreaks", "Image markdown jailbreak", SeverityLevel.MEDIUM),
                ProbeConfig("dan.DAN_Jailbreak", "jailbreaks", "Generic DAN jailbreak", SeverityLevel.HIGH),
                ProbeConfig("dan.DUDE", "jailbreaks", "DUDE jailbreak technique", SeverityLevel.HIGH),
                ProbeConfig("dan.DanInTheWild", "jailbreaks", "Real-world DAN variations", SeverityLevel.HIGH),
                ProbeConfig("dan.DanInTheWildMini", "jailbreaks", "Mini real-world DAN variations", SeverityLevel.MEDIUM),
                ProbeConfig("dan.STAN", "jailbreaks", "STAN jailbreak technique", SeverityLevel.HIGH),
                ProbeConfig("dan.Ablation_Dan_11_0", "jailbreaks", "DAN 11.0 ablation study", SeverityLevel.MEDIUM),
                ProbeConfig("tap.TAP", "jailbreaks", "Tree of Attacks with Pruning", SeverityLevel.CRITICAL),
                ProbeConfig("tap.TAPCached", "jailbreaks", "Cached TAP attacks", SeverityLevel.CRITICAL),
                ProbeConfig("tap.PAIR", "jailbreaks", "PAIR jailbreak technique", SeverityLevel.HIGH),
                ProbeConfig("goodside", "jailbreaks", "Riley Goodside jailbreak collection", SeverityLevel.HIGH),
                ProbeConfig("grandma", "jailbreaks", "Grandma exploit technique", SeverityLevel.MEDIUM),
            ],
            
            "prompt_injection": [
                ProbeConfig("promptinject.HijackHateHumans", "prompt_injection", "Hate humans injection", SeverityLevel.CRITICAL),
                ProbeConfig("promptinject.HijackHateHumansMini", "prompt_injection", "Mini hate humans injection", SeverityLevel.HIGH),
                ProbeConfig("promptinject.HijackKillHumans", "prompt_injection", "Kill humans injection", SeverityLevel.CRITICAL),
                ProbeConfig("promptinject.HijackKillHumansMini", "prompt_injection", "Mini kill humans injection", SeverityLevel.CRITICAL),
                ProbeConfig("promptinject.HijackLongPrompt", "prompt_injection", "Long prompt hijacking", SeverityLevel.HIGH),
                ProbeConfig("promptinject.HijackLongPromptMini", "prompt_injection", "Mini long prompt hijacking", SeverityLevel.MEDIUM),
                ProbeConfig("latentinjection", "prompt_injection", "Latent injection attacks", SeverityLevel.HIGH),
            ],
            
            "encoding": [
                ProbeConfig("encoding.InjectBase64", "encoding", "Base64 encoding injection", SeverityLevel.HIGH),
                ProbeConfig("encoding.InjectBase32", "encoding", "Base32 encoding injection", SeverityLevel.HIGH),
                ProbeConfig("encoding.InjectBase16", "encoding", "Base16/Hex encoding injection", SeverityLevel.HIGH),
                ProbeConfig("encoding.InjectAscii85", "encoding", "ASCII85 encoding injection", SeverityLevel.MEDIUM),
                ProbeConfig("encoding.InjectBase2048", "encoding", "Base2048 encoding injection", SeverityLevel.MEDIUM),
                ProbeConfig("encoding.InjectBraille", "encoding", "Braille encoding injection", SeverityLevel.MEDIUM),
                ProbeConfig("encoding.InjectHex", "encoding", "Hexadecimal encoding injection", SeverityLevel.HIGH),
                ProbeConfig("encoding.InjectMime", "encoding", "MIME encoding injection", SeverityLevel.HIGH),
                ProbeConfig("encoding.InjectMorse", "encoding", "Morse code injection", SeverityLevel.LOW),
                ProbeConfig("encoding.InjectQP", "encoding", "Quoted-printable injection", SeverityLevel.MEDIUM),
                ProbeConfig("encoding.InjectROT13", "encoding", "ROT13 encoding injection", SeverityLevel.LOW),
                ProbeConfig("encoding.InjectUU", "encoding", "UUencoding injection", SeverityLevel.MEDIUM),
            ],
            
            "toxicity": [
                ProbeConfig("atkgen.Tox", "toxicity", "Automated toxicity generation", SeverityLevel.CRITICAL),
                ProbeConfig("realtoxicityprompts", "toxicity", "Real toxicity prompts dataset", SeverityLevel.HIGH),
                ProbeConfig("lmrc.Profanity", "toxicity", "Profanity generation test", SeverityLevel.MEDIUM),
                ProbeConfig("lmrc.Bullying", "toxicity", "Bullying content generation", SeverityLevel.HIGH),
                ProbeConfig("lmrc.SexualContent", "toxicity", "Sexual content generation", SeverityLevel.HIGH),
                ProbeConfig("lmrc.Sexualisation", "toxicity", "Sexualization content", SeverityLevel.HIGH),
                ProbeConfig("lmrc.SlurUsage", "toxicity", "Slur usage detection", SeverityLevel.HIGH),
                ProbeConfig("lmrc.Deadnaming", "toxicity", "Deadnaming behavior", SeverityLevel.MEDIUM),
                ProbeConfig("continuation.ContinueSlursReclaimedSlurs", "toxicity", "Slur continuation test", SeverityLevel.HIGH),
                ProbeConfig("continuation.ContinueSlursReclaimedSlursMini", "toxicity", "Mini slur continuation", SeverityLevel.MEDIUM),
            ],
            
            "malware": [
                ProbeConfig("malwaregen.TopLevel", "malware", "High-level malware generation", SeverityLevel.CRITICAL),
                ProbeConfig("malwaregen.Payload", "malware", "Malware payload generation", SeverityLevel.CRITICAL),
                ProbeConfig("malwaregen.SubFunctions", "malware", "Malware subfunctions", SeverityLevel.HIGH),
                ProbeConfig("malwaregen.Evasion", "malware", "Anti-detection evasion code", SeverityLevel.HIGH),
            ],
            
            "data_leakage": [
                ProbeConfig("leakreplay.GuardianCloze", "data_leakage", "Guardian dataset cloze test", SeverityLevel.HIGH),
                ProbeConfig("leakreplay.GuardianComplete", "data_leakage", "Guardian dataset completion", SeverityLevel.HIGH),
                ProbeConfig("leakreplay.LiteratureCloze", "data_leakage", "Literature cloze test", SeverityLevel.MEDIUM),
                ProbeConfig("leakreplay.LiteratureCloze80", "data_leakage", "Literature cloze 80% test", SeverityLevel.MEDIUM),
                ProbeConfig("leakreplay.LiteratureComplete", "data_leakage", "Literature completion test", SeverityLevel.MEDIUM),
                ProbeConfig("leakreplay.LiteratureComplete80", "data_leakage", "Literature completion 80%", SeverityLevel.MEDIUM),
                ProbeConfig("leakreplay.NYTCloze", "data_leakage", "NYT articles cloze test", SeverityLevel.HIGH),
                ProbeConfig("leakreplay.NYTComplete", "data_leakage", "NYT articles completion", SeverityLevel.HIGH),
                ProbeConfig("leakreplay.PotterCloze", "data_leakage", "Harry Potter cloze test", SeverityLevel.LOW),
                ProbeConfig("leakreplay.PotterComplete", "data_leakage", "Harry Potter completion", SeverityLevel.LOW),
            ],
            
            "hallucination": [
                ProbeConfig("snowball", "hallucination", "Snowball hallucination test", SeverityLevel.MEDIUM),
                ProbeConfig("packagehallucination.Python", "hallucination", "Python package hallucination", SeverityLevel.HIGH),
                ProbeConfig("packagehallucination.JavaScript", "hallucination", "JavaScript package hallucination", SeverityLevel.HIGH),
                ProbeConfig("packagehallucination.Ruby", "hallucination", "Ruby gem hallucination", SeverityLevel.HIGH),
                ProbeConfig("packagehallucination.Rust", "hallucination", "Rust crate hallucination", SeverityLevel.HIGH),
                ProbeConfig("misleading.FalseAssertion50", "hallucination", "False assertions test", SeverityLevel.MEDIUM),
            ],
            
            "specialized": [
                ProbeConfig("xss", "specialized", "Cross-site scripting vulnerabilities", SeverityLevel.CRITICAL),
                ProbeConfig("donotanswer.DiscriminationExclusionToxicityHatefulOffensive", "specialized", "Discrimination content", SeverityLevel.HIGH),
                ProbeConfig("donotanswer.HumanChatbox", "specialized", "Human chatbox simulation", SeverityLevel.MEDIUM),
                ProbeConfig("donotanswer.InformationHazard", "specialized", "Information hazards", SeverityLevel.HIGH),
                ProbeConfig("donotanswer.MaliciousUses", "specialized", "Malicious use cases", SeverityLevel.HIGH),
                ProbeConfig("donotanswer.MisinformationHarms", "specialized", "Misinformation harms", SeverityLevel.HIGH),
                ProbeConfig("lmrc.Anthropomorphisation", "specialized", "Anthropomorphization issues", SeverityLevel.LOW),
                ProbeConfig("lmrc.QuackMedicine", "specialized", "Quack medicine content", SeverityLevel.HIGH),
                ProbeConfig("divergence.Repeat", "specialized", "Repetition divergence", SeverityLevel.LOW),
                ProbeConfig("divergence.RepeatExtended", "specialized", "Extended repetition test", SeverityLevel.LOW),
                ProbeConfig("phrasing.FutureTense", "specialized", "Future tense manipulation", SeverityLevel.LOW),
                ProbeConfig("phrasing.PastTense", "specialized", "Past tense manipulation", SeverityLevel.LOW),
                ProbeConfig("phrasing.TenseMini", "specialized", "Tense manipulation mini", SeverityLevel.LOW),
                ProbeConfig("suffix", "specialized", "Suffix-based attacks", SeverityLevel.MEDIUM),
                ProbeConfig("topic", "specialized", "Topic-based probes", SeverityLevel.MEDIUM),
                ProbeConfig("visual_jailbreak", "specialized", "Visual jailbreak attempts", SeverityLevel.HIGH),
                ProbeConfig("fileformats", "specialized", "File format exploits", SeverityLevel.MEDIUM),
                ProbeConfig("exploitation", "specialized", "General exploitation techniques", SeverityLevel.HIGH),
                ProbeConfig("glitch", "specialized", "Glitch-based attacks", SeverityLevel.MEDIUM),
                ProbeConfig("ansiescape", "specialized", "ANSI escape sequence attacks", SeverityLevel.LOW),
            ],
            
            "antivirus_spam": [
                ProbeConfig("av_spam_scanning.EICAR", "antivirus_spam", "EICAR test string", SeverityLevel.LOW),
                ProbeConfig("av_spam_scanning.GTUBE", "antivirus_spam", "GTUBE spam test", SeverityLevel.LOW),
                ProbeConfig("av_spam_scanning.GTphish", "antivirus_spam", "GTphish phishing test", SeverityLevel.LOW),
            ],
            
            "test": [
                ProbeConfig("test.Test", "test", "Basic functionality test", SeverityLevel.INFO),
            ]
        }
    
    def get_probes_by_category(self, categories: List[ScanCategory]) -> List[str]:
        """Get probe names filtered by categories"""
        selected_probes = []
        
        for category in categories:
            if category == ScanCategory.COMPREHENSIVE:
                # Include all non-test probes for comprehensive scan
                for cat_name, probes in self.probes.items():
                    if cat_name != "test":
                        selected_probes.extend([p.name for p in probes if p.enabled])
            elif category == ScanCategory.JAILBREAKS:
                selected_probes.extend([p.name for p in self.probes["jailbreaks"] if p.enabled])
            elif category == ScanCategory.PROMPT_INJECTION:
                selected_probes.extend([p.name for p in self.probes["prompt_injection"] if p.enabled])
            elif category == ScanCategory.DATA_LEAKAGE:
                selected_probes.extend([p.name for p in self.probes["data_leakage"] if p.enabled])
            elif category == ScanCategory.TOXICITY:
                selected_probes.extend([p.name for p in self.probes["toxicity"] if p.enabled])
            elif category == ScanCategory.MALWARE:
                selected_probes.extend([p.name for p in self.probes["malware"] if p.enabled])
            elif category == ScanCategory.HALLUCINATION:
                selected_probes.extend([p.name for p in self.probes["hallucination"] if p.enabled])
            elif category == ScanCategory.ENCODING:
                selected_probes.extend([p.name for p in self.probes["encoding"] if p.enabled])
        
        return list(set(selected_probes))  # Remove duplicates

class GarakScanner:
    """Advanced Garak scanner with comprehensive security testing capabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.probe_registry = GarakProbeRegistry()
        self.results = {}
        
        # Set up environment variables for API keys
        if config.api_keys:
            for key, value in config.api_keys.items():
                os.environ[key] = value
        
        # Ensure output directory exists
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    
    def _validate_environment(self) -> bool:
        """Validate that garak is installed and accessible"""
        try:
            result = subprocess.run(['python3', '-m', 'garak', '--help'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info("Garak installation validated successfully")
                return True
            else:
                logger.error(f"Garak validation failed: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Failed to validate garak installation: {e}")
            return False
    
    def _build_garak_command(self, probes: List[str]) -> List[str]:
        """Build the garak command with specified parameters"""
        cmd = [
            'python3', '-m', 'garak',
            '--model_type', self.config.model_type,
            '--model_name', self.config.target_model,
            '--report_prefix', os.path.join(self.config.output_dir, self.config.report_prefix),
            '--generations', str(self.config.max_generations)
        ]
        
        if probes:
            cmd.extend(['--probes', ','.join(probes)])
        
        # Add exclude probes if specified
        if self.config.exclude_probes:
            cmd.extend(['--probe_exclude', ','.join(self.config.exclude_probes)])
        
        return cmd
    
    def run_scan_batch(self, probe_batch: List[str], batch_name: str) -> Dict:
        """Run a batch of probes and return results"""
        logger.info(f"Starting scan batch: {batch_name}")
        logger.info(f"Probes in batch: {', '.join(probe_batch)}")
        
        cmd = self._build_garak_command(probe_batch)
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config.timeout,
                cwd=os.getcwd()
            )
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            batch_result = {
                'batch_name': batch_name,
                'probes': probe_batch,
                'duration': scan_duration,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0,
                'timestamp': datetime.now().isoformat()
            }
            
            if result.returncode == 0:
                logger.info(f"Batch {batch_name} completed successfully in {scan_duration:.2f}s")
            else:
                logger.error(f"Batch {batch_name} failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
            
            return batch_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Batch {batch_name} timed out after {self.config.timeout}s")
            return {
                'batch_name': batch_name,
                'probes': probe_batch,
                'duration': self.config.timeout,
                'return_code': -1,
                'stdout': '',
                'stderr': 'Scan timed out',
                'success': False,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Unexpected error in batch {batch_name}: {e}")
            return {
                'batch_name': batch_name,
                'probes': probe_batch,
                'duration': 0,
                'return_code': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False,
                'timestamp': datetime.now().isoformat()
            }
    
    def run_comprehensive_scan(self) -> Dict:
        """Run a comprehensive security scan with all selected probe categories"""
        if not self._validate_environment():
            raise RuntimeError("Garak environment validation failed")
        
        logger.info("Starting comprehensive LLM security scan")
        logger.info(f"Target: {self.config.model_type}:{self.config.target_model}")
        logger.info(f"Categories: {[cat.value for cat in self.config.scan_categories]}")
        
        # Get probes based on selected categories
        selected_probes = self.probe_registry.get_probes_by_category(self.config.scan_categories)
        
        # Add custom probes if specified
        if self.config.custom_probes:
            selected_probes.extend(self.config.custom_probes)
        
        # Remove excluded probes
        if self.config.exclude_probes:
            selected_probes = [p for p in selected_probes if p not in self.config.exclude_probes]
        
        logger.info(f"Total probes to run: {len(selected_probes)}")
        
        # Split probes into batches for parallel execution
        batch_size = max(1, len(selected_probes) // self.config.parallel_probes)
        probe_batches = [selected_probes[i:i + batch_size] 
                        for i in range(0, len(selected_probes), batch_size)]
        
        # Convert config to dict with enum serialization
        config_dict = asdict(self.config)
        config_dict['scan_categories'] = [cat.value for cat in self.config.scan_categories]
        
        scan_results = {
            'scan_config': config_dict,
            'start_time': datetime.now().isoformat(),
            'total_probes': len(selected_probes),
            'batches': [],
            'summary': {}
        }
        
        # Run each batch
        for i, batch in enumerate(probe_batches):
            batch_name = f"batch_{i+1:03d}"
            batch_result = self.run_scan_batch(batch, batch_name)
            scan_results['batches'].append(batch_result)
        
        scan_results['end_time'] = datetime.now().isoformat()
        scan_results['total_duration'] = sum(batch['duration'] for batch in scan_results['batches'])
        scan_results['successful_batches'] = sum(1 for batch in scan_results['batches'] if batch['success'])
        scan_results['failed_batches'] = len(scan_results['batches']) - scan_results['successful_batches']
        
        # Generate summary
        scan_results['summary'] = self._generate_summary(scan_results)
        
        # Save comprehensive results
        self._save_results(scan_results)
        
        return scan_results
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate a summary of scan results"""
        summary = {
            'total_batches': len(scan_results['batches']),
            'successful_batches': scan_results['successful_batches'],
            'failed_batches': scan_results['failed_batches'],
            'success_rate': scan_results['successful_batches'] / len(scan_results['batches']) if scan_results['batches'] else 0,
            'total_runtime': scan_results['total_duration'],
            'average_batch_time': scan_results['total_duration'] / len(scan_results['batches']) if scan_results['batches'] else 0
        }
        
        return summary
    
    def _save_results(self, results: Dict):
        """Save scan results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_path = os.path.join(self.config.output_dir, f"scan_results_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Scan results saved to: {json_path}")
        
        # Generate human-readable report
        report_path = os.path.join(self.config.output_dir, f"scan_report_{timestamp}.md")
        self._generate_markdown_report(results, report_path)
        
        logger.info(f"Scan report saved to: {report_path}")
    
    def _generate_markdown_report(self, results: Dict, output_path: str):
        """Generate a markdown report from scan results"""
        report_content = f"""# LLM Security Scan Report

## Scan Configuration
- **Target Model**: {results['scan_config']['model_type']}:{results['scan_config']['target_model']}
- **Scan Categories**: {', '.join([cat for cat in results['scan_config']['scan_categories']])}
- **Start Time**: {results['start_time']}
- **End Time**: {results['end_time']}
- **Total Duration**: {results['total_duration']:.2f} seconds

## Summary
- **Total Probes**: {results['total_probes']}
- **Total Batches**: {results['summary']['total_batches']}
- **Successful Batches**: {results['summary']['successful_batches']}
- **Failed Batches**: {results['summary']['failed_batches']}
- **Success Rate**: {results['summary']['success_rate']:.1%}
- **Average Batch Time**: {results['summary']['average_batch_time']:.2f}s

## Batch Results

"""
        
        for batch in results['batches']:
            status = "✅ SUCCESS" if batch['success'] else "❌ FAILED"
            report_content += f"""### {batch['batch_name']} - {status}
- **Duration**: {batch['duration']:.2f}s
- **Return Code**: {batch['return_code']}
- **Probes**: {', '.join(batch['probes'])}

"""
            if not batch['success'] and batch['stderr']:
                report_content += f"""**Error Output:**
```
{batch['stderr'][:500]}{'...' if len(batch['stderr']) > 500 else ''}
```

"""
        
        report_content += f"""## Recommendations

Based on the scan results:

1. **Review Failed Batches**: Investigate any failed probe batches for potential issues
2. **Analyze Garak Reports**: Check the detailed JSONL reports generated by Garak in the output directory
3. **Address Vulnerabilities**: Focus on CRITICAL and HIGH severity findings first
4. **Retest**: After implementing fixes, rerun specific probe categories that showed vulnerabilities

## Files Generated
- Detailed JSON results: Available in the output directory
- Garak JSONL reports: Check {results['scan_config']['output_dir']} for detailed probe results
- HTML reports: Generated by Garak for each successful batch

---
*Report generated by Garak LLM Security Scanner Toolkit*
"""
        
        with open(output_path, 'w') as f:
            f.write(report_content)

def create_config_from_args(args) -> ScanConfig:
    """Create scan configuration from command line arguments"""
    scan_categories = []
    
    if args.category:
        for cat in args.category:
            try:
                scan_categories.append(ScanCategory(cat))
            except ValueError:
                logger.warning(f"Unknown category: {cat}")
    
    if not scan_categories:
        scan_categories = [ScanCategory.COMPREHENSIVE]
    
    api_keys = {}
    if args.openai_key:
        api_keys['OPENAI_API_KEY'] = args.openai_key
    if args.anthropic_key:
        api_keys['ANTHROPIC_API_KEY'] = args.anthropic_key
    if args.perspective_key:
        api_keys['PERSPECTIVE_API_KEY'] = args.perspective_key
    if args.cohere_key:
        api_keys['COHERE_API_KEY'] = args.cohere_key
    
    return ScanConfig(
        target_model=args.model_name,
        model_type=args.model_type,
        scan_categories=scan_categories,
        output_dir=args.output_dir,
        report_prefix=args.report_prefix,
        max_generations=args.max_generations,
        timeout=args.timeout,
        parallel_probes=args.parallel_probes,
        custom_probes=args.custom_probes.split(',') if args.custom_probes else None,
        exclude_probes=args.exclude_probes.split(',') if args.exclude_probes else None,
        api_keys=api_keys if api_keys else None
    )

def load_config_from_file(config_path: str) -> ScanConfig:
    """Load scan configuration from YAML file"""
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    
    # Convert string categories to enum
    categories = []
    for cat in config_data.get('scan_categories', ['comprehensive']):
        try:
            categories.append(ScanCategory(cat))
        except ValueError:
            logger.warning(f"Unknown category in config: {cat}")
    
    return ScanConfig(
        target_model=config_data['target_model'],
        model_type=config_data['model_type'],
        scan_categories=categories,
        output_dir=config_data.get('output_dir', './garak_results'),
        report_prefix=config_data.get('report_prefix', 'scan'),
        max_generations=config_data.get('max_generations', 10),
        timeout=config_data.get('timeout', 3600),
        parallel_probes=config_data.get('parallel_probes', 1),
        custom_probes=config_data.get('custom_probes'),
        exclude_probes=config_data.get('exclude_probes'),
        api_keys=config_data.get('api_keys')
    )

def generate_sample_config():
    """Generate a sample configuration file"""
    sample_config = {
        'target_model': 'gpt-3.5-turbo',
        'model_type': 'openai',
        'scan_categories': ['jailbreaks', 'prompt_injection', 'toxicity'],
        'output_dir': './garak_results',
        'report_prefix': 'security_scan',
        'max_generations': 10,
        'timeout': 3600,
        'parallel_probes': 2,
        'custom_probes': None,
        'exclude_probes': ['test.Test'],
        'api_keys': {
            'OPENAI_API_KEY': 'your_openai_key_here',
            'PERSPECTIVE_API_KEY': 'your_perspective_key_here'
        }
    }
    
    with open('garak_config_sample.yaml', 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, indent=2)
    
    print("Sample configuration file generated: garak_config_sample.yaml")

class GarakAnalyzer:
    """Advanced analyzer for Garak scan results"""
    
    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.probe_registry = GarakProbeRegistry()
    
    def analyze_jsonl_reports(self) -> Dict:
        """Analyze JSONL reports generated by Garak"""
        jsonl_files = list(self.results_dir.glob("*.jsonl"))
        
        if not jsonl_files:
            logger.warning("No JSONL report files found")
            return {}
        
        analysis = {
            'total_files': len(jsonl_files),
            'vulnerability_summary': {},
            'probe_results': {},
            'severity_breakdown': {level.value: 0 for level in SeverityLevel},
            'recommendations': []
        }
        
        total_vulnerabilities = 0
        
        for jsonl_file in jsonl_files:
            file_analysis = self._analyze_single_jsonl(jsonl_file)
            
            # Aggregate results
            for probe, results in file_analysis.get('probe_results', {}).items():
                if probe not in analysis['probe_results']:
                    analysis['probe_results'][probe] = {
                        'total_attempts': 0,
                        'failed_attempts': 0,
                        'success_rate': 0,
                        'vulnerabilities': []
                    }
                
                probe_data = analysis['probe_results'][probe]
                probe_data['total_attempts'] += results['total_attempts']
                probe_data['failed_attempts'] += results['failed_attempts']
                probe_data['vulnerabilities'].extend(results['vulnerabilities'])
            
            total_vulnerabilities += file_analysis.get('total_vulnerabilities', 0)
        
        # Calculate success rates and severity breakdown
        for probe, data in analysis['probe_results'].items():
            if data['total_attempts'] > 0:
                data['success_rate'] = (data['failed_attempts'] / data['total_attempts']) * 100
            
            # Get probe severity
            probe_config = self._find_probe_config(probe)
            if probe_config and data['failed_attempts'] > 0:
                analysis['severity_breakdown'][probe_config.severity.value] += data['failed_attempts']
        
        analysis['total_vulnerabilities'] = total_vulnerabilities
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_single_jsonl(self, jsonl_path: Path) -> Dict:
        """Analyze a single JSONL report file"""
        probe_results = {}
        total_vulnerabilities = 0
        
        try:
            with open(jsonl_path, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            record = json.loads(line)
                            
                            probe_name = record.get('probe', 'unknown')
                            status = record.get('status', 'unknown')
                            
                            if probe_name not in probe_results:
                                probe_results[probe_name] = {
                                    'total_attempts': 0,
                                    'failed_attempts': 0,
                                    'vulnerabilities': []
                                }
                            
                            probe_results[probe_name]['total_attempts'] += 1
                            
                            # Check if this represents a vulnerability
                            if status == 'FAIL' or record.get('score', 0) > 0:
                                probe_results[probe_name]['failed_attempts'] += 1
                                probe_results[probe_name]['vulnerabilities'].append({
                                    'prompt': record.get('prompt', ''),
                                    'output': record.get('output', ''),
                                    'score': record.get('score', 0),
                                    'detector': record.get('detector', '')
                                })
                                total_vulnerabilities += 1
                        
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse JSON line in {jsonl_path}: {e}")
                            continue
        
        except Exception as e:
            logger.error(f"Error analyzing {jsonl_path}: {e}")
        
        return {
            'file': str(jsonl_path),
            'probe_results': probe_results,
            'total_vulnerabilities': total_vulnerabilities
        }
    
    def _find_probe_config(self, probe_name: str) -> Optional[ProbeConfig]:
        """Find probe configuration by name"""
        for category_probes in self.probe_registry.probes.values():
            for probe_config in category_probes:
                if probe_config.name == probe_name:
                    return probe_config
        return None
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        total_vulns = analysis['total_vulnerabilities']
        if total_vulns == 0:
            recommendations.append("✅ No vulnerabilities detected in the current scan")
            return recommendations
        
        severity_breakdown = analysis['severity_breakdown']
        
        if severity_breakdown['critical'] > 0:
            recommendations.append(f"🚨 CRITICAL: {severity_breakdown['critical']} critical vulnerabilities found - immediate action required")
        
        if severity_breakdown['high'] > 0:
            recommendations.append(f"⚠️ HIGH: {severity_breakdown['high']} high-severity vulnerabilities - address within 24-48 hours")
        
        if severity_breakdown['medium'] > 0:
            recommendations.append(f"🔶 MEDIUM: {severity_breakdown['medium']} medium-severity vulnerabilities - address within 1 week")
        
        # Specific recommendations based on probe types
        vulnerable_probes = {k: v for k, v in analysis['probe_results'].items() 
                           if v['failed_attempts'] > 0}
        
        if any('dan.' in probe for probe in vulnerable_probes):
            recommendations.append("🔒 Implement stronger jailbreak defenses - DAN vulnerabilities detected")
        
        if any('malwaregen.' in probe for probe in vulnerable_probes):
            recommendations.append("🛡️ Add malware generation filters - model generates potentially harmful code")
        
        if any('promptinject.' in probe for probe in vulnerable_probes):
            recommendations.append("🎯 Strengthen prompt injection defenses - injection attacks successful")
        
        if any('encoding.' in probe for probe in vulnerable_probes):
            recommendations.append("🔤 Implement encoding-aware input validation - bypass techniques working")
        
        if any('leakreplay.' in probe for probe in vulnerable_probes):
            recommendations.append("🔐 Review training data exposure - potential data leakage detected")
        
        recommendations.append("📊 Run follow-up scans after implementing fixes to verify improvements")
        
        return recommendations
    
    def generate_detailed_report(self, output_path: str):
        """Generate a detailed analysis report"""
        analysis = self.analyze_jsonl_reports()
        
        report_content = f"""# Detailed Garak Security Analysis Report

## Executive Summary
- **Total Vulnerabilities Found**: {analysis['total_vulnerabilities']}
- **Files Analyzed**: {analysis['total_files']}
- **Report Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Severity Breakdown
"""
        
        for severity, count in analysis['severity_breakdown'].items():
            if count > 0:
                emoji = {'critical': '🚨', 'high': '⚠️', 'medium': '🔶', 'low': '🔵', 'info': 'ℹ️'}.get(severity, '•')
                report_content += f"- **{severity.upper()}**: {count} {emoji}\n"
        
        report_content += "\n## Probe Results\n\n"
        
        for probe, data in analysis['probe_results'].items():
            if data['failed_attempts'] > 0:
                probe_config = self._find_probe_config(probe)
                severity = probe_config.severity.value if probe_config else 'unknown'
                
                report_content += f"""### {probe} ({severity})
- **Total Attempts**: {data['total_attempts']}
- **Failed Attempts**: {data['failed_attempts']}
- **Failure Rate**: {data['success_rate']:.1f}%
- **Description**: {probe_config.description if probe_config else 'N/A'}

"""
        
        report_content += "\n## Recommendations\n\n"
        for i, rec in enumerate(analysis['recommendations'], 1):
            report_content += f"{i}. {rec}\n"
        
        report_content += f"""
## Next Steps

1. **Prioritize Critical Issues**: Address all CRITICAL and HIGH severity vulnerabilities immediately
2. **Implement Defenses**: Add appropriate input validation, output filtering, and safety measures
3. **Monitor**: Set up regular security scanning as part of your CI/CD pipeline
4. **Test**: Verify fixes by re-running specific probe categories
5. **Document**: Keep records of vulnerabilities found and remediation steps taken

---
*Detailed analysis generated by Garak LLM Security Scanner Toolkit*
"""
        
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        logger.info(f"Detailed analysis report saved to: {output_path}")

def main():
    """Main function with comprehensive CLI interface"""
    parser = argparse.ArgumentParser(
        description="Comprehensive Garak LLM Security Scanner Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default settings
  python garak_scanner.py --model-type openai --model-name gpt-3.5-turbo
  
  # Comprehensive security audit
  python garak_scanner.py --model-type huggingface --model-name gpt2 --category comprehensive
  
  # Specific category testing
  python garak_scanner.py --model-type openai --model-name gpt-4 --category jailbreaks toxicity
  
  # Load configuration from file
  python garak_scanner.py --config config.yaml
  
  # Generate sample configuration
  python garak_scanner.py --generate-config
  
  # Analyze existing results
  python garak_scanner.py --analyze ./results
"""
    )
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('--config', type=str, help='Load configuration from YAML file')
    config_group.add_argument('--generate-config', action='store_true', help='Generate sample configuration file')
    
    # Model options
    model_group = parser.add_argument_group('Model Configuration')
    model_group.add_argument('--model-type', type=str, 
                           choices=['openai', 'huggingface', 'anthropic', 'cohere', 'replicate', 'ollama', 'test'],
                           help='Type of model to scan')
    model_group.add_argument('--model-name', type=str, help='Specific model name to scan')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('--category', type=str, nargs='+',
                          choices=[cat.value for cat in ScanCategory],
                          help='Security categories to test')
    scan_group.add_argument('--custom-probes', type=str, help='Comma-separated list of custom probes')
    scan_group.add_argument('--exclude-probes', type=str, help='Comma-separated list of probes to exclude')
    scan_group.add_argument('--max-generations', type=int, default=10, help='Maximum generations per probe')
    scan_group.add_argument('--timeout', type=int, default=3600, help='Timeout in seconds for each batch')
    scan_group.add_argument('--parallel-probes', type=int, default=1, help='Number of parallel probe batches')
    
    # Output options
    output_group = parser.add_argument_group('Output Configuration')
    output_group.add_argument('--output-dir', type=str, default='./garak_results', help='Output directory for results')
    output_group.add_argument('--report-prefix', type=str, default='scan', help='Prefix for report files')
    
    # API Keys
    api_group = parser.add_argument_group('API Keys')
    api_group.add_argument('--openai-key', type=str, help='OpenAI API key')
    api_group.add_argument('--anthropic-key', type=str, help='Anthropic API key')
    api_group.add_argument('--perspective-key', type=str, help='Perspective API key')
    api_group.add_argument('--cohere-key', type=str, help='Cohere API key')
    
    # Analysis options
    analysis_group = parser.add_argument_group('Analysis')
    analysis_group.add_argument('--analyze', type=str, help='Analyze existing results in specified directory')
    
    # Utility options
    utility_group = parser.add_argument_group('Utilities')
    utility_group.add_argument('--list-probes', action='store_true', help='List all available probes by category')
    utility_group.add_argument('--validate', action='store_true', help='Validate Garak installation')
    
    args = parser.parse_args()
    
    # Handle utility commands
    if args.generate_config:
        generate_sample_config()
        return
    
    if args.list_probes:
        registry = GarakProbeRegistry()
        print("\n=== Available Garak Probes by Category ===\n")
        for category, probes in registry.probes.items():
            print(f"📁 {category.upper()}:")
            for probe in probes:
                status = "✅" if probe.enabled else "❌"
                print(f"  {status} {probe.name} - {probe.description} [{probe.severity.value}]")
            print()
        return
    
    if args.validate:
        scanner = GarakScanner(ScanConfig(
            target_model="test", model_type="test", scan_categories=[ScanCategory.TEST],
            output_dir="./test", report_prefix="test"
        ))
        if scanner._validate_environment():
            print("✅ Garak installation is valid and ready to use")
        else:
            print("❌ Garak installation validation failed")
        return
    
    if args.analyze:
        analyzer = GarakAnalyzer(args.analyze)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"analysis_report_{timestamp}.md"
        analyzer.generate_detailed_report(report_path)
        print(f"Analysis complete. Report saved to: {report_path}")
        return
    
    # Main scanning functionality
    try:
        if args.config:
            config = load_config_from_file(args.config)
        else:
            if not args.model_type or not args.model_name:
                parser.error("--model-type and --model-name are required unless using --config")
            config = create_config_from_args(args)
        
        scanner = GarakScanner(config)
        results = scanner.run_comprehensive_scan()
        
        print(f"\n=== Scan Complete ===")
        print(f"Total Duration: {results['total_duration']:.2f}s")
        print(f"Successful Batches: {results['successful_batches']}/{len(results['batches'])}")
        print(f"Results saved to: {config.output_dir}")
        
        # Automatically run analysis if scan completed successfully
        if results['successful_batches'] > 0:
            print("\n=== Running Analysis ===")
            analyzer = GarakAnalyzer(config.output_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_path = os.path.join(config.output_dir, f"analysis_report_{timestamp}.md")
            analyzer.generate_detailed_report(analysis_path)
            print(f"Analysis report saved to: {analysis_path}")
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()