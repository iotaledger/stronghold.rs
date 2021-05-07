# Notes on the custom network behaviour

**Send Query:**

```none
          |  Query      ResponseChannel-->Response   Swarm.poll()         
          |   |                       /|\   /|\        /|\                  
          |   V peer, request          |     |          | ::ReceiveResponse 
__________| _________________________________|______________________________
Network   | fn send_request            |     | fn inject_event              
Behaviour |                            |     |         /|\                  
          |  (tx,rx)=channel<Response> |     |          | HandlerOutEvent:: 
          |                            |     |          | Received          
          |     | ______ rx ___________'     |          | Omission          
          |     |                            |          | Timeout           
          |     |                            |          | Unsupported       
          |     V request, tx                |          | _Protocols        
__________|__________________________________|__________| __________________
Handler   | fn inject_event                  | fn inject_negotiated_outbound
          |     |                            |         /|\                  
          |     | request, tx                |          |                   
          |     V                            |          |                   
__________|__________________________________|______________________________
new       | fn upgrade_outbound              |          |                   
Outbound- |                                  |          |                   
Protocol  |  write substream (request)       |          | send_res.ok()     
          |  ... await                       |          |                   
          |  response = read substream       |          |                   
          |                                  |          |                   
          |  send_res = tx.send(response) ___|          |                   
          |    | _______________________________________|                   
```

**Decisions:**
- inbound requests: drop request on connection closed / firewall rejected / ... without creating a behaviour event to inform the user
- firewall:
  - bounded mpsc channel to send firewall requests
    - to demand rules for a specific peer if there are no default rules
    - to get approval for a specific request in case of `Rule::Ask`
    - each firewall requests includes a oneshot channel to return the response
  - default rules:
    - use default rules if no peer specific rule
    - if default rule is none, send `FirewallRequest::PeerSpecificRule` through firewall channel to demand a rule
