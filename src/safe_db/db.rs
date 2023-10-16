use std::collections::{BTreeMap, HashMap, HashSet};

use crate::types::{edge::EdgeDB, Address, Edge, Safe, U256};

#[derive(Debug)]
pub struct DB {
    safes: BTreeMap<Address, Safe>,
    token_owner: BTreeMap<Address, Address>,
    edges: EdgeDB,
}

impl DB {
    pub fn new(safes: BTreeMap<Address, Safe>, token_owner: BTreeMap<Address, Address>) -> DB {
        println!("{} safes, {} tokens", safes.len(), token_owner.len());
        let mut db = DB {
            safes,
            token_owner,
            edges: EdgeDB::new(vec![]),
        };
        db.compute_edges_new();
        println!("{} edges", db.edges.edge_count());
        db
    }

    pub fn safes(&self) -> &BTreeMap<Address, Safe> {
        &self.safes
    }

    pub fn edges(&self) -> &EdgeDB {
        &self.edges
    }

    fn compute_edges(&mut self) {
        // Universal computation of edges
        // Let's assume that any "token" is represented by the address of its owner in the edges
        // We also assume that the "send_to" relationship is the opposite to the trust relationship
        // List of edges
        let mut edges = vec![];
        // Create the edges from the token holders to anyone who trusts that token
        for (user, safe) in &self.safes {
            for (token, balance) in &safe.balances {
                if let Some(owner) = self.token_owner.get(token) {
                    if *balance != U256::from(0) {
                        if let Some(owner_safe) = self.safes.get(owner) {
                            // "limit_percentage" represents the list of users that accept the "owner_safe"'s token
                            for (send_to, percentage) in &owner_safe.limit_percentage {
                                if percentage == &0 || *user == *send_to {
                                    continue;
                                }
                                if let Some(receiver_safe) = self.safes.get(send_to) {
                                    // If the receiver is an organization, the edge's limit is the balance of the
                                    // sender, i.e., the user can send all their tokens to an organization.
                                    // Likewise, if the receiver is the owner of the token, the edge's limit is
                                    // the sender's balance of that token.
                                    let limit: U256 = if receiver_safe.organization
                                        || *owner == *send_to
                                    {
                                        *balance
                                    } else {
                                        // TODO it should not be "min" - the second constraint
                                        // is set by the balance edge.
                                        safe.trust_transfer_limit(receiver_safe, *percentage, token)
                                    };
                                    if limit != U256::from(0) {
                                        edges.push(Edge {
                                            from: *user,
                                            to: *send_to,
                                            token: *owner,
                                            capacity: limit,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        self.edges = EdgeDB::new(edges)
    }

    fn compute_edges_new(&mut self) {
        let mut edges: Vec<Edge> = vec![];

        // taken from https://github.com/CirclesUBI/pathfinder2/commit/5950ab81b2d1adf36354e3b9e7bc5b16e0a97874?diff=unified
        // to address the original issue #43, https://github.com/CirclesUBI/pathfinder2/pull/43
        // however, this exposes a combinatorially large growth of extra edges, which are redundant
        // as the same path over an organisation can always be achieved over the token owner
        // (with max +1 hop-in, and max +1 hop-out)

        // token address -> orga addresses
        let mut organization_accepted_tokens: HashMap<Address, HashSet<Address>> = HashMap::new();

        // Build a map from token address to orga addresses that accept this token
        for (_, safe) in &self.safes {
            for (send_to, percentage) in &safe.limit_percentage {
                if percentage == &0 {
                    continue;
                }

                let receiver_safe = self.safes.get(send_to).unwrap();
                if receiver_safe.organization {
                    //println!("user {} can send {} token to orga {}", user, safe.token_address, send_to);
                    organization_accepted_tokens.entry(safe.token_address).or_default().insert(*send_to);
                }
            }
        }

        // Find all safes that have a non-zero balance of tokens that are accepted by an organization
        for (user, safe) in &self.safes {
            for (token, balance) in &safe.balances {
                if balance == &U256::from(0) {
                    continue;
                }
                if *token == safe.token_address {
                    // this is the token of the user itself, and these edges are already covered below
                    // we don't want to double-add.
                    continue;
                }
                organization_accepted_tokens.get(token).map(|organizations| {
                    for organization in organizations {
                        // Add the balance as capacity from 'user' to 'organization'
                        edges.push(Edge {
                            from: *user,
                            to: *organization,
                            token: *token,
                            capacity: *balance,
                        });
                    }
                });
            }
        }

        // For all nodes in the graph
        for (user, safe) in &self.safes {
            // Loop over all explicit trust connections;
            // here, safe.limit_percentage is the inverted map of all the safes
            // that trust this safe (as opposed to the contract state,
            // which stores all the safes a safe trusts)
            if safe.organization {
                println!("{} is an organization", user);
                println!("{} is trusted by {}", user, safe.limit_percentage.len());
                // assert!(safe.limit_percentage.len() == 0, "Organization is not trusted by anyone");
            }
            for (send_to, percentage) in &safe.limit_percentage {
                if *user == *send_to || *percentage == 0 {
                    // skip self-loops and zero-percentage edges
                    continue;
                }
                
                if let Some(receiver_safe) = self.safes.get(send_to) {
                    let limit: U256 = if receiver_safe.organization {
                        // println!("{} is an organization that trusts {}", send_to, user);
                        if safe.balance(&safe.token_address) > U256::from(0) {
                            println!("EDGE from {} to ORG {} with limit {}", user, send_to, safe.balance(&safe.token_address));
                        }
                        // If the receiver is an organization,
                        // the edge's limit is the balance of the sender (ie. user) (see return value)
                        // However, if an organisation trust a person, 

                        safe.balance(&safe.token_address)
                    } else {
                        // Calculate the maximum amount user can transfer to the receiver
                        // based on the trust percentage and the balance of the receiver's tokens.
                        safe.trust_transfer_limit(receiver_safe, *percentage, &safe.token_address)
                    };
                    if limit != U256::from(0) {
                        edges.push(Edge {
                            from: *user,
                            to: *send_to,
                            token: *user,
                            capacity: limit,
                        });
                    }
                }
            }

            // Loop over all implicit trust connections;
            // but limit implicit edges only to sending tokens back to original owner;
            // ie. edges could be created between two safes that mutually trust a shared safe,
            // and one of them holds tokens from the shared safe. In this case `trust_transfer_limit`
            // would allow the holding safe to push tokens to the other safe,
            // but this combinatorially increases the number of edges in the graph
            // - and the number of edges is the main bottleneck in the computation.
            for (token, balance) in &safe.balances {
                if safe.organization {
                    println!("{} is an ORG that holds {} of {}", user, balance, token);
                }
                if let Some(owner) = self.token_owner.get(token) {
                    if *user != *owner && *balance != U256::from(0) {
                        edges.push(Edge {
                            from: *user,
                            to: *owner,
                            token: *owner,
                            capacity: *balance,
                        });
                    }
                }
            }
        }
        self.edges = EdgeDB::new(edges)
    }
}
