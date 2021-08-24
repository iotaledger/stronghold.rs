# Stronghold Rules Engine

The rules engine for Stronghold is being used for setting up forward chaining rules being applied
at runtime to allow / disallow certain types of actions. One such scenario within the context of 
stronghold is defining a synchronization rule between two Stronghold snapshots. 
The rule engine offers the flexibility to work on certain states of stronghold
and store them in a consise manner to control the behavior from a central point. 

This example shows the definition of a rule for complete 
synchronization between two snapshots. All client_paths that will appear in
a diff will be merged in a new snapshot:

```
// alias 
use stronghold_rules as rules;

// import macro and rules engine
use rules::{RulesEngine, Rule, rule!};
use stronghold::Stronghold;
use actix;

#[actix::main]
async fn main() {
    let stronghold  = Stronghold::init_stronghold();
    let engine      = RuleEngine::new();
    let local_synchronize_rule = rule!("synchronize snapshot locally", 

    ),

	
}

```













# --- algorithm description

The Rete algorithm uses a rooted acyclic directed graph, the Rete, where the nodes, with the exception of the root, represent patterns, and paths from the root to the leaves represent left-hand sides of rules. At each node is stored information about the facts satisfied by the patterns of the nodes in the paths from the root up to and including this node. This information is a relation representing the possible values of the variables occurring in the patterns in the path.

The Rete algorithm keeps up to date the information associated with the nodes in the graph. When a fact is added or removed from working memory, a token representing that fact and operation is entered at the root of the graph and propagated to its leaves modifying as appropriate the information associated with the nodes. When a fact is modified, say, the age of John is changed from 20 to 21, this is expressed as a deletion of the old fact (the age of John is 20) and the addition of a new fact (the age of John is 21). We will consider only additions of facts.

The Rete consists of the root node, of one-input pattern nodes, and of two input join nodes.

The root node has as successors one-input "kind" nodes, one for each possible kind of fact (the kind of a fact is its first component). When a token arrives to the root a copy of that token is sent to each "kind" node where a SELECT operation is carried out that selects only the tokens of its kind.

Then for each rule and each of its patterns we create a one input alpha node. Each "kind" node is connected to all the alpha nodes of its kind and delivers to them copies of the tokens it receives. To each alpha node is associated a relation, the Alpha Memory, whose columns are named by the variables appearing in the node's pattern. For example, if the pattern for the node is (is-a-parent-of ?x ?y) then the relation has columns named X and Y. When a token arrives to the alpha node a PROJECT operation extracts from the token tuple's the components that match the variables of the pattern. The resulting tuple is added to the alpha memory of the node.

Then, for each rule Ri, if Ai,1 Ai,2 ... Ai,n are in order the alpha nodes of the rule, we construct two-input nodes, called Beta Nodes, Bi,2 Bi,3 ... Bi,n where

	Bi,2 has its left input from Ai,1 and its right input from Ai,2

	Bi,j, for j greater than 2, has its left input from Bi,j-1
	and its right input from Ai,j

At each beta node Bi,j we store a relation, the Beta Memory, which is the JOIN of the relations associated to its left and right input, joined on the columns named by variables that occur in both relations. For example if the left input relation and right input relations are:

	X	Y		X	Z
	=========		=========
	ann	4		ann	tom
	sam	22		ann	sue
				tom	jane

    then the resulting beta memory relation is

	X	Y	Z
	=================
	ann	4	tom
	ann	4	sue

Finally the last beta node of each rule is connected to a new alpha node where a PROJECT operation takes place to select all and only the variables that occur on the right-hand side of the rule.