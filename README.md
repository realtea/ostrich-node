#RUN AS ROOT and MAKE SURE PORTS: 80,443 OF YOUR SERVER ARE OPEN TO PUBLIC
###### #0 run the following command on your terminal
### ./install.sh

###### #1 start your node, then check if your node been correctly started

### ./start.sh

###### #2 create your user
### ./ostrich/ostrich_cli  create  user  ****(replace this with your own username )

#Q & A
## #0 How long should I wait to connect the node?
    3 mins later, after your node been started
## #1 How to check log file?
    tail -f /etc/ostrich/logs/ostrich.log
## #2 How to check the traffic status of node?
    watch -n 1 'netstat -ant|grep 443|grep ESTABLISHED'
