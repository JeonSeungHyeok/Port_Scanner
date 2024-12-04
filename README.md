# Port_Scanner
```
██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║   
██╔═══╝ ██║   ██║██╔══██╗   ██║   
██║     ╚██████╔╝██║  ██║   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```
### Usage

<hr>

1. You have to start setup to use this package
    - the setup file is Under ```SETUP``` dir
    - Windows : ```setup.bat```
    - Linux or Mac : ```setup.sh```
2. the setup script requires an argument
    - ```install``` : make an docker image ```p0f``` ( if your platform is Windows you have to run docker-desktop before executing setup file )
    - ```remove``` : remove an docker image ```p0f```
3. After setup completed you can execute the code with command following
    - ```python3 main.py```
4. The ```main.py``` code require several options
    ```
    $ python3 main.py
      usage: python3 main.py <ip> [-S] [-A] [-N] [-X] -P PORT [-T THREADS] [-t TIME] [-M TRIES] [-OS] [-oj] [-ox] [-sV] [-v]
    ```
    - ```-S``` : TCP SYN scan
    - ```-A``` : TCP ACK scan
    - ```-N``` : TCP Null scan
    - ```-X``` : TCP X-mas scan
    - ```-P``` : Specify port range ( e.g., '22,80,443' or '20-80' )
    - ```-T``` : Specify number of threads ( default : 1 )
    - ```-M``` : Maximum Tries
    - ```-O``` : Detect OS
    - ```-t``` : Response Time
    - ```-v``` : Search CVE
    - ```-oj``` : Output JSON
    - ```-ox``` : Output XML
    - ```-sV``` : Service Version
    