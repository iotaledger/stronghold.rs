# Notes on the custom network behaviour

**Send Request:**

```none
          |  Request      ResponseChannel-->Response   Swarm.poll()         
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
