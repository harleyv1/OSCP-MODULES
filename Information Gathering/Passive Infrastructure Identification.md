
---

[Netcraft](https://www.netcraft.com/) can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view. We can use the service by visiting `https://sitereport.netcraft.com` and entering the target domain.

![](https://academy.hackthebox.com/storage/modules/144/netcraft_facebook.png)

Some interesting details we can observe from the report are:

| | |
|---|---|
|`Background`|General information about the domain, including the date it was first seen by Netcraft crawlers.|
|`Network`|Information about the netblock owner, hosting company, nameservers, etc.|
|`Hosting history`|Latest IPs used, webserver, and target OS.|

## Wayback Machine

The [Internet Archive](https://en.wikipedia.org/wiki/Internet_Archive) is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

We can access several versions of these websites using the [Wayback Machine](http://web.archive.org/) to find old versions that may have interesting comments in the source code or files that should not be there. This tool can be used to find older versions of a website at a point in time. Let's take a website running WordPress, for example.

  
![image](https://academy.hackthebox.com/storage/modules/144/wayback1.png)

We can check one of the first versions of `facebook.com` captured on December 1, 2005, which is interesting, perhaps gives us a sense of nostalgia but is also extremely useful for us as security researchers.

![](https://academy.hackthebox.com/storage/modules/144/wayback2.png)

We can also use the tool [waybackurls](https://github.com/tomnomnom/waybackurls) to inspect URLs saved by Wayback Machine and look for specific keywords. Provided we have `Go` set up correctly on our host, we can install the tool as follows:

```shell
Pwn1Sec@htb[/htb]$ go install github.com/tomnomnom/waybackurls@latest
```

To get a list of crawled URLs from a domain with the date it was obtained, we can add the `-dates` switch to our command as follows:

```shell
Pwn1Sec@htb[/htb]$ waybackurls -dates https://facebook.com > waybackurls.txt
Pwn1Sec@htb[/htb]$ cat waybackurls.txt

2018-05-20T09:46:07Z http://www.facebook.com./
2018-05-20T10:07:12Z https://www.facebook.com/
2018-05-20T10:18:51Z http://www.facebook.com/#!/pages/Welcome-Baby/143392015698061?ref=tsrobots.txt
2018-05-20T10:19:19Z http://www.facebook.com/
2018-05-20T16:00:13Z http://facebook.com
2018-05-21T22:12:55Z https://www.facebook.com
2018-05-22T15:14:09Z http://www.facebook.com
2018-05-22T17:34:48Z http://www.facebook.com/#!/Syerah?v=info&ref=profile/robots.txt
2018-05-23T11:03:47Z http://www.facebook.com/#!/Bin595

<SNIP>
```

If we want to access a specific resource, we need to place the URL in the search menu and navigate to the date when the snapshot was created. As stated previously, Wayback Machine can be a handy tool and should not be overlooked. It can very likely lead to us discovering forgotten assets, pages, etc., which can lead to discovering a flaw.

 [Previous](https://academy.hackthebox.com/module/144/section/1252)

 Mark Complete & Next

[Next](https://academy.hackthebox.com/module/144/section/1255) 

 Cheat Sheet

##### Table of Contents

[Information Gathering](https://academy.hackthebox.com/module/144/section/1247)

###### Passive Information Gathering

  [WHOIS](https://academy.hackthebox.com/module/144/section/1248)  [DNS](https://academy.hackthebox.com/module/144/section/1251)[Passive Subdomain Enumeration](https://academy.hackthebox.com/module/144/section/1252)[Passive Infrastructure Identification](https://academy.hackthebox.com/module/144/section/1253)

###### Active Information Gathering

  [Active Infrastructure Identification](https://academy.hackthebox.com/module/144/section/1255)  [Active Subdomain Enumeration](https://academy.hackthebox.com/module/144/section/1256)  [Virtual Hosts](https://academy.hackthebox.com/module/144/section/1257)[Crawling](https://academy.hackthebox.com/module/144/section/1258)

###### Putting it all Together

  [Information Gathering - Web - Skills Assessment](https://academy.hackthebox.com/module/144/section/1311)

##### My Workstation

OFFLINE

  Start Instance

 / 1 spawns left