//! The closed vocabularies. Nothing outside these lists can be stored or rendered.

macro_rules! closed_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $var:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($(#[$vm])* $var),+ }
        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$var),+];
            /// The wire string.
            pub fn as_str(self) -> &'static str { match self { $($name::$var => $s),+ } }
            /// Parse a wire string; `None` for anything outside the closed list.
            pub fn parse(s: &str) -> Option<$name> { match s { $($s => Some($name::$var),)+ _ => None } }
        }
    };
}

closed_enum!(
    /// The three tenants (sites).
    Tenant {
        /// entropa.space
        Entropa => "entropa",
        /// bigironbank.online
        Bigironbank => "bigironbank",
        /// hippagrchealthcare.site
        Hippagrchealthcare => "hippagrchealthcare",
    }
);

closed_enum!(
    /// Role-based public handles. Crew names are never handles (docs/ARCHITECTURE-EXPLORER.md section 8).
    Handle {
        /// The accountable human (keyless; attested by the orchestrator).
        HumanPrincipal => "human-principal",
        /// Reviews and approves.
        OrchestratorAgent => "orchestrator-agent",
        /// Writes and tests code.
        BuilderAgent => "builder-agent",
        /// Added when it exists.
        OperatorAgent => "operator-agent",
        /// Signs checkpoints.
        LogSigner => "log-signer",
        /// The synthetic scenario generator.
        Generator => "generator",
        /// The Azure witness.
        WitnessAzure => "witness-azure",
        /// The AWS KMS co-signer.
        CosignerAwsKms => "cosigner-aws-kms",
        /// The entropa site agent.
        AgentEntropa => "agent-entropa",
        /// The bank site agent.
        AgentBigironbank => "agent-bigironbank",
        /// The clinic site agent.
        AgentHippagrchealthcare => "agent-hippagrchealthcare",
        /// Reviews recorded decisions and files findings.
        CriticAgent => "critic-agent",
        /// Argues against the findings.
        ContestorAgent => "contestor-agent",
        /// An advisory AI reviewer of the public bundles.
        ObserverAgent => "observer-agent",
        /// Opens and closes council sessions.
        SchedulerAgent => "scheduler-agent",
    }
);

closed_enum!(
    /// Kinds of events this crate owns (other record types come from the approvals, policy and witness crates).
    Kind {
        /// An AI model call (hashes and counts only).
        AgentInvocation => "agent.invocation",
        /// A synthetic transaction decision.
        TxScreened => "tx.screened",
        /// An actor entered the directory.
        DirectoryActor => "directory.actor",
        /// An AI decision in the platinum layer (hashes and counts only).
        PlatinumDecision => "platinum.decision",
        /// A pipeline run (counts and a hash, never data).
        EvidencePipelineRun => "evidence.pipeline_run",
        /// A security or data-safety control check.
        EvidenceControlCheck => "evidence.control_check",
        /// A data access decision.
        EvidenceAccess => "evidence.access",
        /// A change: deploy, rollback, schema change or key rotation.
        EvidenceChange => "evidence.change",
        /// A policy event.
        EvidencePolicy => "evidence.policy",
        /// One step of a decision review council session (hashes and closed codes only).
        CouncilStep => "council.step",
    }
);

closed_enum!(
    /// What the event is about, as a code.
    LabelCode {
        /// Fraud screening of a synthetic transaction.
        FraudScreen => "fraud_screen",
        /// Review of a synthetic case.
        CaseReview => "case_review",
        /// A question answered about the audit log.
        AuditQuestion => "audit_question",
        /// An actor was registered.
        ActorRegistered => "actor_registered",
        /// An English question turned into read-only SQL.
        NlQuery => "nl_query",
        /// A model score over platinum features.
        MlScore => "ml_score",
        /// A retrieval-augmented answer.
        RagAnswer => "rag_answer",
        /// Bronze layer run.
        Bronze => "bronze",
        /// Silver layer run.
        Silver => "silver",
        /// Gold layer run.
        Gold => "gold",
        /// Platinum layer run.
        Platinum => "platinum",
        /// Row-level security test.
        RlsTest => "rls_test",
        /// Masking check.
        MaskingCheck => "masking_check",
        /// k-anonymity check.
        KAnonymity => "k_anonymity",
        /// Canary leak scan.
        CanaryScan => "canary_scan",
        /// Identifier-range check.
        IdentifierRange => "identifier_range",
        /// Secret scan.
        SecretScan => "secret_scan",
        /// CI test run.
        CiTests => "ci_tests",
        /// A table read.
        TableRead => "table_read",
        /// A deploy.
        Deploy => "deploy",
        /// A rollback.
        Rollback => "rollback",
        /// A schema change.
        SchemaChange => "schema_change",
        /// A key rotation.
        KeyRotation => "key_rotation",
        /// A policy approval.
        PolicyApproved => "policy_approved",
        /// A code change (a commit).
        CodeChange => "code_change",
        /// A council session event (opened, closed, no quorum).
        CouncilSession => "council_session",
        /// The review packet was compiled.
        CouncilPacket => "council_packet",
        /// A critic finding.
        CouncilFinding => "council_finding",
        /// A contestor rebuttal.
        CouncilRebuttal => "council_rebuttal",
        /// The Human Principal decided a finding.
        CouncilDecision => "council_decision",
        /// A claims-triage decision (a platinum.decision label): an action chosen for a denied claim.
        ClaimsTriage => "claims_triage",
        /// A policy gate verdict on a proposed action (an evidence.policy label).
        PolicyVerdict => "policy_verdict",
        /// A human approval was requested for a case (an evidence.policy label; decision hold).
        ApprovalRequested => "approval_requested",
        /// A human approval was denied or expired (an evidence.policy label).
        ApprovalDenied => "approval_denied",
        /// A case outcome checked against the decision (an evidence.control_check label).
        CaseOutcome => "case_outcome",
        /// A listing of the TLS settings of our own hosts (an evidence.control_check label).
        CryptoInventory => "crypto_inventory",
        /// A ledger verified from start to end, or a verification failure (an evidence.control_check label).
        LogIntegrityCheck => "log_integrity_check",
        /// A standards corpus version was sealed, or refused because a source changed under the same version name (an evidence.change label; counts: total = clauses, passed = sources sealed, flagged = sources that changed).
        CorpusVersion => "corpus_version",
        /// A retrieval from the sealed standards corpus was answered or abstained (an evidence.access label; counts: total = 1 query or the passages returned, passed = passages returned, flagged = 1 when it abstained).
        RetrievalRecord => "retrieval_record",
    }
);

closed_enum!(
    /// The decision, as a code.
    Decision {
        /// Allowed.
        Allow => "allow",
        /// Denied.
        Deny => "deny",
        /// Held for review.
        Hold => "hold",
        /// Escalated to a human gate.
        Escalate => "escalate",
        /// Released.
        Release => "release",
        /// Informational.
        Info => "info",
    }
);

closed_enum!(
    /// Why, as a code.
    ReasonCode {
        /// No special reason.
        None => "none",
        /// The policy denied.
        PolicyDeny => "policy_deny",
        /// An approval is pending.
        GatePending => "gate_pending",
        /// An approval was denied.
        GateDenied => "gate_denied",
        /// A human decision is required.
        HumanRequired => "human_required",
        /// Within limits.
        WithinLimits => "within_limits",
        /// Needs review.
        NeedsReview => "needs_review",
        /// Cited receipts.
        CitedReceipts => "cited_receipts",
        /// The SQL guard accepted the query.
        GuardPassed => "guard_passed",
        /// The SQL guard refused the query.
        GuardRefused => "guard_refused",
        /// Input looked like a prompt injection.
        InjectionSuspected => "injection_suspected",
        /// A check passed.
        CheckPassed => "check_passed",
        /// A check failed.
        CheckFailed => "check_failed",
        /// The council accepted the item.
        CouncilAccepted => "council_accepted",
        /// The council rejected the item.
        CouncilRejected => "council_rejected",
        /// The council deferred the item.
        CouncilDeferred => "council_deferred",
        /// The session could not meet its quorum, so nothing changes.
        CouncilNoQuorum => "council_no_quorum",
    }
);

closed_enum!(
    /// Who ran a model.
    Provider {
        /// Amazon Bedrock.
        Bedrock => "bedrock",
        /// Vertex AI.
        Vertex => "vertex",
        /// A test double.
        Fake => "fake",
        /// A model run locally (llama.cpp).
        Local => "local",
        /// Spark MLlib.
        Sparkml => "sparkml",
        /// Azure (Microsoft models).
        Azure => "azure",
    }
);

closed_enum!(
    /// An actor's role.
    RoleCode {
        /// A person.
        Human => "human",
        /// An AI agent.
        Ai => "ai",
        /// A service.
        Service => "service",
    }
);

closed_enum!(
    /// The control an evidence event supports (names only; no framework text is reproduced).
    ControlCode {
        /// HIPAA Security Rule: security management process.
        Hipaa164308a1 => "hipaa_164_308_a1",
        /// HIPAA Security Rule: information access management.
        Hipaa164308a4 => "hipaa_164_308_a4",
        /// HIPAA Security Rule: access control.
        Hipaa164312a1 => "hipaa_164_312_a1",
        /// HIPAA Security Rule: audit controls.
        Hipaa164312b => "hipaa_164_312_b",
        /// HIPAA Security Rule: integrity.
        Hipaa164312c1 => "hipaa_164_312_c1",
        /// HIPAA Security Rule: person or entity authentication.
        Hipaa164312d => "hipaa_164_312_d",
        /// HIPAA Security Rule: transmission security.
        Hipaa164312e1 => "hipaa_164_312_e1",
        /// HITRUST category: access control.
        Hitrust01AccessControl => "hitrust_01_access_control",
        /// HITRUST category: compliance.
        Hitrust06Compliance => "hitrust_06_compliance",
        /// HITRUST category: communications and operations management.
        Hitrust09Operations => "hitrust_09_operations",
        /// HITRUST category: systems acquisition, development and maintenance.
        Hitrust10Sdlc => "hitrust_10_sdlc",
        /// HITRUST category: privacy practices.
        Hitrust13Privacy => "hitrust_13_privacy",
        /// Our policy P0: data safety.
        PolicyP0DataSafety => "policy_p0_data_safety",
        /// Our policy P3: separation of duties.
        PolicyP3SeparationOfDuties => "policy_p3_separation_of_duties",
        /// PCI DSS 10.3.4: change detection on audit logs (name only).
        PciDss10_3_4 => "pci_dss_10_3_4",
        /// PCI DSS 12.3.3: cryptographic suites and protocols inventory (name only).
        PciDss12_3_3 => "pci_dss_12_3_3",
        /// DORA RTS Article 6: encryption and cryptographic controls (name only).
        DoraRtsArt6 => "dora_rts_art_6",
        /// DORA RTS Article 12: logging (name only).
        DoraRtsArt12 => "dora_rts_art_12",
        /// NIST SP 800-53 AU-9: protection of audit information (name only).
        Nist80053Au9 => "nist_800_53_au_9",
        /// NIST SP 800-53 AU-10: non-repudiation (name only).
        Nist80053Au10 => "nist_800_53_au_10",
        /// EU AI Act Article 12: record-keeping (name only).
        EuAiActArt12 => "eu_ai_act_art_12",
        /// EU AI Act Article 19: automatically generated logs (name only).
        EuAiActArt19 => "eu_ai_act_art_19",
    }
);

impl Kind {
    /// True for the audit-evidence kinds.
    pub fn is_evidence(self) -> bool {
        matches!(
            self,
            Kind::EvidencePipelineRun
                | Kind::EvidenceControlCheck
                | Kind::EvidenceAccess
                | Kind::EvidenceChange
                | Kind::EvidencePolicy
        )
    }
}
