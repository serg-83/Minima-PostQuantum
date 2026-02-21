package org.minima.system.network.rpc;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.minima.utils.MinimaLogger;

public abstract class HTTPServer extends Server implements Runnable{

	/**
	 * Max concurrent HTTP handler threads to prevent thread exhaustion DoS
	 * Максимум одновременных HTTP-потоков для защиты от DoS через исчерпание потоков
	 */
	private static final int MAX_HANDLER_THREADS = 16;

	ServerSocket mServerSocket;

	ExecutorService mThreadPool;

	boolean mRunning = true;
	
	public HTTPServer(int zPort) {
		this(zPort, true);
	}
	
	public HTTPServer(int zPort, boolean zAutoStart) {
		super(zPort);
		
		if(zAutoStart) {
			start();
		}
	}
	
	@Override
	public void shutdown() {
		mRunning = false;

		try {
			if(mServerSocket != null) {
				mServerSocket.close();
			}
		} catch (Exception e) {
			MinimaLogger.log(e);
		}

		if(mThreadPool != null) {
			mThreadPool.shutdown();
			try {
				mThreadPool.awaitTermination(5, TimeUnit.SECONDS);
			} catch (InterruptedException e) {}
			mThreadPool.shutdownNow();
		}
	}
	
	public void start() {
		Thread runner = new Thread(this);
		runner.start();
	}
	
	public abstract Runnable getSocketHandler(Socket zSocket);
	
	@Override
	public void run() {
		try {
			//Start a server Socket..
			mServerSocket = new ServerSocket(mPort);

			//Thread pool instead of unbounded thread creation
			//Пул потоков вместо неограниченного создания потоков
			mThreadPool = Executors.newFixedThreadPool(MAX_HANDLER_THREADS);

			MinimaLogger.log("Server started on port : "+mPort);

			//Keep listening..
			while(mRunning) {
				//Listen in for connections
				Socket clientsock = mServerSocket.accept();

				//Get the Handler..
				Runnable handler = getSocketHandler(clientsock);

				//Run in thread pool instead of creating new thread each time
				mThreadPool.execute(handler);
			}
			
		} catch (BindException e) {
			//Socket shut down..
			MinimaLogger.log("Server @ Port "+mPort+" already in use!.. restart required..");
			
		} catch (SocketException e) {
			if(mRunning) {
				//Socket shut down..
				MinimaLogger.log("RPCServer : Socket Shutdown.. "+e);
			}
		} catch (IOException e) {
			MinimaLogger.log(e);
		}
	}
}