
使用时需要添加 --variable SECRECT=value   value为https秘钥

例git@fileshare.mobit.eu:cordova/https.git --variable SECRECT=value

https证书需要三个

      1.client.bks  安卓使用
      
      2.client.p12  安卓/iOS使用
      
      3.server.der  iOS使用
      
这三个文件都要放在src/assets下
