# 2Ddoc-checking

Created by Alexis STOELTZLEN and Thérèse FILI for a cryptographic project.

## Purpose 

This repository contains a Java code that allows you to verify a 2D-doc.

## Contents of the repository

There are 3 folders :
- images folder : contains 2D-doc images that have been verified by the code
- src : contains the source code
- jarLib : contains the .jar that we used to install libraries

## Installation

You can download the repository and then you will need to install the librairies needed. To realise that, you have to go
on File > Project Structure > Librairies, choose javase and add the .jar contained in the jarLib folder. Then apply and that's it.
This is the method if you use the IntelliJ IDE.

## Usage

Open the project and go into the Decrypt 2D-doc class. Then, at line 33, you can indicate the path to a 2D-doc image you want to 
decrypt and verify. Please, note that this code doesn't support the 01 version of 2D-doc.
