package org.minima.system.network.rpc;

import java.io.IOException;
import java.net.BindException;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.minima.utils.MinimaLogger;
import org.minima.utils.ssl.SSLManager;
 
public abstract class HTTPSServer extends Server implements Runnable {
    
	/**
	 * Max concurrent HTTPS handler threads to prevent thread exhaustion DoS
	 * Максимум одновременных HTTPS-потоков для защиты от DoS через исчерпание потоков
	 */
	private static final int MAX_HANDLER_THREADS = 16;

	private boolean mShutdown 	= false;

    SSLServerSocket mSSLServerSocket = null;

    ExecutorService mThreadPool;
    
    public HTTPSServer(int port){
        super(port);
    	
        //Run it..
		Thread tt = new Thread(this);
		tt.start();
    }
    
    @Override
    public void shutdown() {
    	try {
    		mShutdown = true;

    		if(mSSLServerSocket != null) {
    			mSSLServerSocket.close();
    		}
		} catch (IOException e) {
			e.printStackTrace();
		}

		if(mThreadPool != null) {
			mThreadPool.shutdown();
			try {
				mThreadPool.awaitTermination(5, TimeUnit.SECONDS);
			} catch (InterruptedException e) {}
			mThreadPool.shutdownNow();
		}
    }
    
    public abstract Runnable getSocketHandler(SSLSocket zSocket);
	
    // Create the and initialize the SSLContext
    private SSLContext createSSLContext(){
        try{
        	
        	//Get the Key store
        	KeyStore keyStore = SSLManager.getSSLKeyStore();
        	
            //Get the Factory
            KeyManagerFactory keyManagerFactory = SSLManager.getSSLKeyFactory(keyStore);
            
            //Get the Key manager
            KeyManager[] km = keyManagerFactory.getKeyManagers();
             
            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();
             
            // Initialise SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(km,  tm, null);
             
            return sslContext;
        } catch (Exception ex){
            ex.printStackTrace();
        }
         
        return null;
    }
     
    @Override
    public void run(){
        SSLContext sslContext = this.createSSLContext();
         
        try{
            // Create server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
             
            // Create server socket
            mSSLServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.mPort);
             
            //Thread pool instead of unbounded thread creation
            //Пул потоков вместо неограниченного создания потоков
            mThreadPool = Executors.newFixedThreadPool(MAX_HANDLER_THREADS);

            MinimaLogger.log("SSL server started on port "+mPort);
            while(!mShutdown){

            	//Get the socket
            	SSLSocket sslSocket = (SSLSocket) mSSLServerSocket.accept();

            	//Get the Handler..
				Runnable handler = getSocketHandler(sslSocket);

				//Run in thread pool instead of creating new thread each time
				mThreadPool.execute(handler);
            }
        
        } catch (BindException e) {
			//Socket shut down..
			MinimaLogger.log("SSL Server @ Port "+mPort+" already in use!.. restart required..");
		
        } catch (Exception ex){
        	if(!mShutdown) {
        		MinimaLogger.log(ex);
        	}
        }
    }
}