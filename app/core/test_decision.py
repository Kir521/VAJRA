from app.core.decision_engine import DecisionEngine


engine = DecisionEngine()

test_scores = [10, 35, 65, 90]

print("\n===== VAJRA DECISION ENGINE =====")

for score in test_scores:

    result = engine.decide(score)

    print("\nRisk Score:", score)
    print("Action:", result["action"])
    print("Severity:", result["severity"])
    print("Message:", result["message"])