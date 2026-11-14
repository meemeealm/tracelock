# Reproducible entry points. The agent seed is fixed (demo/agent_scripted.py: DEFAULT_SEED = 1234).
PYTHON ?= python3

.PHONY: install test demo attacks bench groq openai clean

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

demo:            # witness process + scripted agent + verifier + HTML report -> out/run_all/report.html
	$(PYTHON) -m demo.run_all

attacks:         # the six tamper scenarios, as a markdown table
	$(PYTHON) -m attacks.tamper

bench:           # overhead microbenchmark (1000 spans per configuration)
	$(PYTHON) -m bench.overhead

groq:            # needs network, GROQ_API_KEY and GROQ_MODEL in .env
	$(PYTHON) -m demo.agent_groq --provider groq --record

openai:          # needs network, OPENAI_API_KEY and OPENAI_MODEL in .env
	$(PYTHON) -m demo.agent_groq --provider openai --record

clean:
	rm -rf out .pytest_cache; find . -name __pycache__ -prune -exec rm -rf {} +
