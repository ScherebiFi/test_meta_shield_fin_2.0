from __future__ import annotations

import os
from typing import Any


def is_configured() -> bool:
    return all(
        os.getenv(name)
        for name in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD")
    )


def read_network(limit: int = 50) -> dict[str, Any]:
    if not is_configured():
        return {
            "connected": False,
            "nodes": [],
            "relationships": [],
            "message": "Connecteur Neo4j non configuré.",
        }

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"]),
    )
    try:
        driver.verify_connectivity()
        with driver.session() as session:
            result = session.run(
                """MATCH (source)-[relation]->(target)
                RETURN labels(source) AS source_labels, type(relation) AS relation,
                       labels(target) AS target_labels
                LIMIT $limit""",
                limit=limit,
            )
            links = [
                {
                    "source_labels": record["source_labels"],
                    "relation": record["relation"],
                    "target_labels": record["target_labels"],
                }
                for record in result
            ]
    finally:
        driver.close()

    return {
        "connected": True,
        "nodes": [],
        "relationships": links,
        "message": f"{len(links)} relation(s) lue(s) depuis Neo4j.",
    }